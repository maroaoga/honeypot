import csv
import json

import joblib
import pandas as pd
import pytest

from database.db import create_event, create_session, initialize_database
from features.extractor import FEATURE_COLUMNS
from ml.train import train_and_evaluate


def _create_labeled_sessions(db_path, labels_path, *, copies=6, offset=0):
    examples = []
    event_by_label = {
        "brute_force": ("tcp_login_attempt", {"username": "admin", "password_length": 8}),
        "port_scan": ("tcp_connection", {"service": "fake_login"}),
        "sql_injection": ("http_login_attempt", {"username": "' OR '1'='1", "password_length": 4}),
        "directory_probe": ("http_request", {"path": "/admin"}),
        "benign": ("http_login_attempt", {"username": "alice", "password_length": 12}),
    }
    for label, (event_type, details) in event_by_label.items():
        for index in range(copies):
            session_id = create_session("127.0.0.1", db_path=db_path)
            create_event(session_id, event_type, details, db_path=db_path)
            examples.append((session_id, label))
    with open(labels_path, "w", newline="", encoding="utf-8") as labels_file:
        writer = csv.writer(labels_file)
        writer.writerow(("session_id", "label"))
        writer.writerows(examples)
    return examples


def test_training_saves_model_metrics_and_separate_seed_evaluation(tmp_path):
    db_path = tmp_path / "training.db"
    initialize_database(db_path)
    labels_path = tmp_path / "train-labels.csv"
    different_seed_path = tmp_path / "different-seed-labels.csv"
    _create_labeled_sessions(db_path, labels_path)
    _create_labeled_sessions(db_path, different_seed_path, copies=2)
    model_path = tmp_path / "model.joblib"
    metrics_path = tmp_path / "metrics.json"

    metrics = train_and_evaluate(
        labels_path,
        db_path=db_path,
        different_seed_labels_path=different_seed_path,
        model_path=model_path,
        metrics_path=metrics_path,
        cv_folds=3,
    )

    assert model_path.exists()
    artifact = joblib.load(model_path)
    assert artifact["classes"] == sorted(artifact["classes"])
    assert "label" not in artifact["feature_columns"]
    assert metrics["cross_validation"]["folds"] == 3
    assert metrics["stratified_test"]["sample_count"] == 8
    assert metrics["different_seed_evaluation"]["sample_count"] == 10
    assert metrics["isolation_forest_baseline"]["sample_count"] == 8
    assert set(metrics["stratified_test"]) >= {
        "macro_precision",
        "macro_recall",
        "macro_f1",
        "macro_false_positive_rate",
        "confusion_matrix",
    }
    saved_metrics = json.loads(metrics_path.read_text(encoding="utf-8"))
    assert saved_metrics == metrics
    exported_features = pd.read_csv(tmp_path / "session_features.csv")
    assert list(exported_features.columns) == ["session_id", *FEATURE_COLUMNS]
    assert "label" not in exported_features.columns
    assert (tmp_path / "feature_means_by_class.csv").exists()
    assert (tmp_path / "feature_missing_zero_summary.csv").exists()
    assert (tmp_path / "feature_importances.csv").exists()
    assert (tmp_path / "confusion_matrix.csv").exists()
    assert (tmp_path / "cross_validation_scores.csv").exists()
    assert "logistic_regression_baseline" in metrics


def test_training_rejects_duplicate_session_labels(tmp_path):
    db_path = tmp_path / "training.db"
    initialize_database(db_path)
    session_id = create_session("127.0.0.1", db_path=db_path)
    labels_path = tmp_path / "duplicate.csv"
    labels_path.write_text(
        f"session_id,label\n{session_id},benign\n{session_id},brute_force\n",
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="duplicate session_id"):
        train_and_evaluate(
            labels_path,
            db_path=db_path,
            model_path=tmp_path / "model.joblib",
            metrics_path=tmp_path / "metrics.json",
        )


def test_training_rejects_too_few_examples_for_stratification(tmp_path):
    db_path = tmp_path / "training.db"
    initialize_database(db_path)
    labels_path = tmp_path / "few-labels.csv"
    _create_labeled_sessions(db_path, labels_path, copies=1)

    with pytest.raises(ValueError, match="at least two sessions"):
        train_and_evaluate(
            labels_path,
            db_path=db_path,
            model_path=tmp_path / "model.joblib",
            metrics_path=tmp_path / "metrics.json",
        )


def test_training_rejects_labels_without_matching_sessions(tmp_path):
    db_path = tmp_path / "training.db"
    initialize_database(db_path)
    labels_path = tmp_path / "missing-session.csv"
    labels_path.write_text("session_id,label\n123,benign\n", encoding="utf-8")

    with pytest.raises(ValueError, match="no extracted features"):
        train_and_evaluate(
            labels_path,
            db_path=db_path,
            model_path=tmp_path / "model.joblib",
            metrics_path=tmp_path / "metrics.json",
        )
