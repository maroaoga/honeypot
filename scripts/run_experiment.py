"""Generate the configured datasets, fit the model, and save reproducible results."""

import argparse
import csv
import json
import logging
import shutil
import sqlite3
from time import perf_counter
from collections import Counter
from dataclasses import asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import joblib
import matplotlib
import pandas as pd
import yaml

from database.db import initialize_database
from features.extractor import FEATURE_COLUMNS
from integration.run import _service_ports, run_pipeline
from ml.train import train_and_evaluate
from simulator.runner import (
    load_simulation_config,
    run_simulation,
)


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_RESULTS_DIR = ROOT / "results"
DEFAULT_TRAIN_CONFIG = ROOT / "config" / "simulator.yaml"
DEFAULT_EVALUATION_CONFIG = ROOT / "config" / "simulator_evaluation.yaml"
DEFAULT_INTEGRATION_CONFIG = ROOT / "config" / "integration.yaml"
GENERATED_FILES = (
    "experiment.db",
    "evaluation.db",
    "train_labels.csv",
    "different_seed_labels.csv",
    "integration_labels.csv",
    "simulator_config.yaml",
    "evaluation_config.yaml",
    "experiment_summary.json",
    "integration_run.json",
    "random_forest.joblib",
    "metrics.json",
    "session_features.csv",
    "feature_head.csv",
    "feature_means_by_class.csv",
    "feature_missing_zero_summary.csv",
    "feature_importances.csv",
    "top_feature_importances.csv",
    "confusion_matrix.csv",
    "cross_validation_scores.csv",
    "confusion_matrix.png",
    "feature_importance.png",
)
def _read_labels(path: Path) -> list[tuple[int, str]]:
    with path.open(newline="", encoding="utf-8") as labels_file:
        reader = csv.DictReader(labels_file)
        if reader.fieldnames != ["session_id", "label"]:
            raise ValueError(f"Labels file '{path}' has an invalid schema.")
        return [(int(row["session_id"]), row["label"]) for row in reader]


def _database_summary(
    db_path: Path,
    labels_path: Path,
    config_path: Path,
    *,
    date_generated: str,
) -> dict[str, Any]:
    labels = _read_labels(labels_path)
    class_counts = Counter(label for _, label in labels)
    with sqlite3.connect(db_path) as connection:
        connection.execute(
            "CREATE TEMP TABLE experiment_labels "
            "(session_id INTEGER PRIMARY KEY, label TEXT NOT NULL)"
        )
        connection.executemany(
            "INSERT INTO experiment_labels (session_id, label) VALUES (?, ?)",
            labels,
        )
        event_counts = {
            str(label): int(count)
            for label, count in connection.execute(
                "SELECT experiment_labels.label, COUNT(events.id) "
                "FROM experiment_labels LEFT JOIN events "
                "ON events.session_id = experiment_labels.session_id "
                "GROUP BY experiment_labels.label"
            ).fetchall()
        }
        source_count = int(
            connection.execute(
                "SELECT COUNT(DISTINCT sessions.source_ip) "
                "FROM sessions JOIN experiment_labels "
                "ON sessions.id = experiment_labels.session_id"
            ).fetchone()[0]
        )
        brute_force_attempts = connection.execute(
            "SELECT MIN(attempt_count), AVG(attempt_count), MAX(attempt_count) "
            "FROM (SELECT COUNT(events.id) AS attempt_count "
            "FROM experiment_labels JOIN events "
            "ON events.session_id = experiment_labels.session_id "
            "WHERE experiment_labels.label = ? AND events.event_type = ? "
            "GROUP BY experiment_labels.session_id)",
            ("brute_force", "tcp_login_attempt"),
        ).fetchone()

    config_data = yaml.safe_load(config_path.read_text(encoding="utf-8"))
    total_sessions = len(labels)
    return {
        "date_generated_utc": date_generated,
        "config_file": config_path.name,
        "seed": int(config_data["seed"]),
        "total_sessions": total_sessions,
        "session_counts_by_class": dict(sorted(class_counts.items())),
        "class_percentages": {
            label: count * 100 / total_sessions
            for label, count in sorted(class_counts.items())
        },
        "event_counts_by_class": dict(sorted(event_counts.items())),
        "total_events": sum(event_counts.values()),
        "unique_loopback_source_ips": source_count,
        "brute_force_attempts_per_session": {
            "minimum": int(brute_force_attempts[0] or 0),
            "mean": float(brute_force_attempts[1] or 0),
            "maximum": int(brute_force_attempts[2] or 0),
        },
        "simulator_config": config_data,
        "labels_file": labels_path.name,
    }


def _read_model_importances(model_path: Path) -> dict[str, float] | None:
    if not model_path.is_file():
        return None
    artifact = joblib.load(model_path)
    if not isinstance(artifact, dict) or not isinstance(
        artifact.get("feature_columns"), list
    ):
        return None
    columns = artifact["feature_columns"]
    model = artifact.get("model")
    if not hasattr(model, "feature_importances_"):
        return None
    return {
        feature: float(value)
        for feature, value in zip(columns, model.feature_importances_)
    }


def _create_plots(results_dir: Path, metrics: dict[str, Any]) -> None:
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    import numpy as np

    matrix = metrics["stratified_test"]["confusion_matrix"]
    labels = matrix["labels_in_order"]
    values = np.asarray(matrix["values"])
    figure, axis = plt.subplots(figsize=(8, 6), constrained_layout=True)
    image = axis.imshow(values, cmap="Blues")
    figure.colorbar(image, ax=axis, label="Sessions")
    axis.set(
        xticks=range(len(labels)),
        xticklabels=labels,
        yticks=range(len(labels)),
        yticklabels=labels,
        xlabel="Predicted class",
        ylabel="Actual class",
        title="Random Forest test confusion matrix",
    )
    plt.setp(axis.get_xticklabels(), rotation=35, ha="right", rotation_mode="anchor")
    threshold = values.max() / 2 if values.size else 0
    for row in range(values.shape[0]):
        for column in range(values.shape[1]):
            axis.text(
                column,
                row,
                str(values[row, column]),
                ha="center",
                va="center",
                color="white" if values[row, column] > threshold else "black",
            )
    figure.savefig(results_dir / "confusion_matrix.png", dpi=160)
    plt.close(figure)

    importance = pd.read_csv(results_dir / "feature_importances.csv").head(12)
    figure, axis = plt.subplots(figsize=(9, 6), constrained_layout=True)
    axis.barh(importance["feature"][::-1], importance["importance"][::-1], color="#3267a8")
    axis.set(xlabel="Mean impurity importance", title="Top Random Forest feature importances")
    figure.savefig(results_dir / "feature_importance.png", dpi=160)
    plt.close(figure)


def _write_json(path: Path, value: Any) -> None:
    path.write_text(
        json.dumps(value, indent=2, allow_nan=False) + "\n",
        encoding="utf-8",
    )


def _remove_previous_outputs(results_dir: Path) -> None:
    for name in GENERATED_FILES:
        output = results_dir / name
        if output.is_file():
            output.unlink()
        elif output.exists():
            raise IsADirectoryError(f"Expected a generated file, found directory '{output}'.")


def run_experiment(
    *,
    results_dir: str | Path = DEFAULT_RESULTS_DIR,
    train_config_path: str | Path = DEFAULT_TRAIN_CONFIG,
    evaluation_config_path: str | Path = DEFAULT_EVALUATION_CONFIG,
) -> dict[str, Any]:
    """Run isolated training/evaluation datasets and the model-backed integration flow."""
    experiment_started = perf_counter()
    output_dir = Path(results_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    _remove_previous_outputs(output_dir)
    train_config_file = Path(train_config_path)
    evaluation_config_file = Path(evaluation_config_path)
    train_config = load_simulation_config(train_config_file)
    evaluation_config = load_simulation_config(evaluation_config_file)
    shutil.copyfile(train_config_file, output_dir / "simulator_config.yaml")
    shutil.copyfile(
        evaluation_config_file,
        output_dir / "evaluation_config.yaml",
    )

    train_db = output_dir / "experiment.db"
    evaluation_db = output_dir / "evaluation.db"
    train_labels = output_dir / "train_labels.csv"
    evaluation_labels = output_dir / "different_seed_labels.csv"
    for db_path in (train_db, evaluation_db):
        initialize_database(db_path)

    train_started = datetime.now(timezone.utc).isoformat()
    with _service_ports(train_db) as (tcp_port, web_port):
        training_sessions = run_simulation(
            train_config,
            labels_path=train_labels,
            db_path=train_db,
            tcp_port=tcp_port,
            web_port=web_port,
        )
    evaluation_started = datetime.now(timezone.utc).isoformat()
    with _service_ports(evaluation_db) as (tcp_port, web_port):
        evaluation_sessions = run_simulation(
            evaluation_config,
            labels_path=evaluation_labels,
            db_path=evaluation_db,
            tcp_port=tcp_port,
            web_port=web_port,
        )
    if training_sessions != 1500 or evaluation_sessions != 1500:
        raise RuntimeError(
            "The experiment configs must each generate exactly 300 sessions per class."
        )

    train_summary = _database_summary(
        train_db,
        train_labels,
        train_config_file,
        date_generated=train_started,
    )
    evaluation_summary = _database_summary(
        evaluation_db,
        evaluation_labels,
        evaluation_config_file,
        date_generated=evaluation_started,
    )
    for dataset_name, summary in (
        ("training", train_summary),
        ("different-seed evaluation", evaluation_summary),
    ):
        if summary["session_counts_by_class"] != {
            "benign": 300,
            "brute_force": 300,
            "directory_probe": 300,
            "port_scan": 300,
            "sql_injection": 300,
        }:
            raise RuntimeError(
                f"The {dataset_name} dataset does not contain 300 sessions per class."
            )
        if summary["unique_loopback_source_ips"] < 3:
            raise RuntimeError(
                f"The {dataset_name} dataset did not use at least three loopback sources."
            )
    previous_importances = _read_model_importances(
        ROOT / "ml" / "random_forest.joblib"
    )
    results = train_and_evaluate(
        train_labels,
        db_path=train_db,
        model_path=output_dir / "random_forest.joblib",
        metrics_path=output_dir / "metrics.json",
        different_seed_labels_path=evaluation_labels,
        different_seed_db_path=evaluation_db,
    )
    importance = pd.read_csv(output_dir / "feature_importances.csv")
    importance.head(10).to_csv(
        output_dir / "top_feature_importances.csv",
        index=False,
    )
    _create_plots(output_dir, results)

    train_summary["features"] = [
        {"name": column, "dtype": str(dtype)}
        for column, dtype in zip(
            FEATURE_COLUMNS,
            pd.read_csv(output_dir / "session_features.csv", nrows=1).dtypes[1:],
        )
    ]
    train_summary["feature_columns"] = list(FEATURE_COLUMNS)
    train_summary["label_in_feature_columns"] = False
    new_importances = dict(
        zip(importance["feature"], importance["importance"].astype(float))
    )
    new_ranked = sorted(new_importances, key=new_importances.get, reverse=True)
    train_summary["legacy_payload_length_importance"] = (
        previous_importances.get("payload_length_chars")
        if previous_importances
        else None
    )
    train_summary["new_payload_length_importance"] = new_importances[
        "payload_length_chars"
    ]
    train_summary["legacy_payload_length_rank"] = (
        sorted(previous_importances, key=previous_importances.get, reverse=True).index(
            "payload_length_chars"
        )
        + 1
        if previous_importances and "payload_length_chars" in previous_importances
        else None
    )
    train_summary["new_payload_length_rank"] = (
        new_ranked.index("payload_length_chars") + 1
    )
    train_summary["payload_length_importance_decreased"] = (
        train_summary["legacy_payload_length_importance"] is not None
        and train_summary["new_payload_length_importance"]
        < train_summary["legacy_payload_length_importance"]
    )
    train_summary["payload_length_rank_changed"] = (
        train_summary["legacy_payload_length_rank"] is not None
        and train_summary["new_payload_length_rank"]
        != train_summary["legacy_payload_length_rank"]
    )
    train_summary["payload_length_remains_most_important"] = (
        train_summary["new_payload_length_rank"] == 1
    )
    report_summary = {
        "training": train_summary,
        "different_seed_evaluation": evaluation_summary,
        "metrics_file": "metrics.json",
        "feature_head_file": "feature_head.csv",
        "feature_means_file": "feature_means_by_class.csv",
        "feature_importance_file": "feature_importances.csv",
        "confusion_matrix_plot": "confusion_matrix.png",
        "feature_importance_plot": "feature_importance.png",
    }
    integration_result = run_pipeline(
        config=load_simulation_config(DEFAULT_INTEGRATION_CONFIG),
        db_path=train_db,
        labels_path=output_dir / "integration_labels.csv",
        model_path=output_dir / "random_forest.joblib",
    )
    integration_summary = asdict(integration_result)
    _write_json(output_dir / "integration_run.json", integration_summary)
    report_summary["experiment_wall_seconds"] = perf_counter() - experiment_started
    _write_json(output_dir / "experiment_summary.json", report_summary)
    return {
        "training_sessions": training_sessions,
        "evaluation_sessions": evaluation_sessions,
        "training_metrics": results["stratified_test"],
        "different_seed_metrics": results["different_seed_evaluation"],
        "integration": integration_summary,
        "experiment_wall_seconds": report_summary["experiment_wall_seconds"],
        "results_directory": str(output_dir),
    }


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(
        description="Generate the full reproducible honeypot experiment."
    )
    parser.add_argument("--results", type=Path, default=DEFAULT_RESULTS_DIR)
    parser.add_argument("--config", type=Path, default=DEFAULT_TRAIN_CONFIG)
    parser.add_argument(
        "--evaluation-config",
        type=Path,
        default=DEFAULT_EVALUATION_CONFIG,
    )
    args = parser.parse_args(argv)
    result = run_experiment(
        results_dir=args.results,
        train_config_path=args.config,
        evaluation_config_path=args.evaluation_config,
    )
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    logging.basicConfig(level=logging.WARNING)
    main()
