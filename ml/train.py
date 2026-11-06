"""Train and evaluate a Random Forest from separately stored session labels."""

import argparse
import csv
import json
import logging
from pathlib import Path
from typing import Any

import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest, RandomForestClassifier
from sklearn.metrics import (
    accuracy_score,
    confusion_matrix,
    f1_score,
    precision_score,
    precision_recall_fscore_support,
    recall_score,
)
from sklearn.metrics import make_scorer
from sklearn.model_selection import StratifiedKFold, cross_validate, train_test_split

from database.db import DEFAULT_DB_PATH
from features.extractor import extract_features
from simulator.runner import DEFAULT_LABELS_PATH


logger = logging.getLogger(__name__)
DEFAULT_MODEL_PATH = Path(__file__).with_name("random_forest.joblib")
DEFAULT_METRICS_PATH = Path(__file__).with_name("metrics.json")
DEFAULT_RANDOM_STATE = 42
DEFAULT_CV_FOLDS = 5
DEFAULT_TEST_SIZE = 0.25
DEFAULT_TREE_COUNT = 100


def _read_labels(labels_path: str | Path) -> pd.Series:
    path = Path(labels_path)
    labels: dict[int, str] = {}
    try:
        with path.open(newline="", encoding="utf-8") as labels_file:
            reader = csv.DictReader(labels_file)
            if reader.fieldnames != ["session_id", "label"]:
                raise ValueError("Labels CSV must have exactly 'session_id,label' columns.")
            for row_number, row in enumerate(reader, start=2):
                try:
                    session_id = int(row["session_id"])
                except (TypeError, ValueError) as exc:
                    raise ValueError(
                        f"Labels CSV row {row_number} has an invalid session_id."
                    ) from exc
                label = row["label"]
                if session_id < 1:
                    raise ValueError(f"Labels CSV row {row_number} has a non-positive session_id.")
                if not isinstance(label, str) or not label.strip():
                    raise ValueError(f"Labels CSV row {row_number} has an empty label.")
                if session_id in labels:
                    raise ValueError(f"Labels CSV contains duplicate session_id {session_id}.")
                labels[session_id] = label.strip()
    except OSError:
        logger.exception("Could not read labels CSV '%s'.", path)
        raise
    if not labels:
        raise ValueError(f"Labels CSV '{path}' contains no labeled sessions.")
    return pd.Series(labels, name="label", dtype="string")


def _load_dataset(
    labels_path: str | Path,
    db_path: str | Path,
) -> tuple[pd.DataFrame, pd.Series]:
    labels = _read_labels(labels_path)
    features = extract_features(db_path)
    missing_ids = labels.index.difference(features.index)
    if not missing_ids.empty:
        preview = ", ".join(str(session_id) for session_id in missing_ids[:5])
        raise ValueError(
            f"{len(missing_ids)} labeled session(s) have no extracted features: {preview}."
        )
    selected_features = features.loc[labels.index]
    if selected_features.empty or not all(
        pd.api.types.is_numeric_dtype(dtype) for dtype in selected_features.dtypes
    ):
        raise ValueError("Training features must be a non-empty numeric DataFrame.")
    return selected_features, labels


def _validate_training_options(
    *,
    test_size: float,
    random_state: int,
    cv_folds: int,
) -> None:
    if isinstance(test_size, bool) or not isinstance(test_size, (int, float)):
        raise ValueError("test_size must be a number between 0 and 1.")
    if not 0 < test_size < 1:
        raise ValueError("test_size must be a number between 0 and 1.")
    if type(random_state) is not int or random_state < 0:
        raise ValueError("random_state must be a non-negative integer.")
    if type(cv_folds) is not int or cv_folds < 2:
        raise ValueError("cv_folds must be an integer of at least 2.")


def _class_counts(labels: pd.Series) -> dict[str, int]:
    return {str(label): int(count) for label, count in labels.value_counts().items()}


def _classification_metrics(
    y_true: pd.Series,
    y_pred: np.ndarray,
    classes: list[str],
) -> dict[str, Any]:
    precision, recall, f1, support = precision_recall_fscore_support(
        y_true,
        y_pred,
        labels=classes,
        zero_division=0,
    )
    matrix = confusion_matrix(y_true, y_pred, labels=classes)
    false_positive_rates = []
    for class_index in range(len(classes)):
        true_positive = int(matrix[class_index, class_index])
        false_negative = int(matrix[class_index, :].sum() - true_positive)
        false_positive = int(matrix[:, class_index].sum() - true_positive)
        true_negative = int(matrix.sum() - true_positive - false_negative - false_positive)
        denominator = false_positive + true_negative
        false_positive_rates.append(
            false_positive / denominator if denominator else 0.0
        )

    return {
        "sample_count": int(len(y_true)),
        "accuracy": float(accuracy_score(y_true, y_pred)),
        "macro_precision": float(np.mean(precision)),
        "macro_recall": float(np.mean(recall)),
        "macro_f1": float(np.mean(f1)),
        "macro_false_positive_rate": float(np.mean(false_positive_rates)),
        "false_positive_rate_definition": (
            "Mean of per-class one-vs-rest FP/(FP+TN) values."
        ),
        "per_class": {
            label: {
                "precision": float(precision[index]),
                "recall": float(recall[index]),
                "f1": float(f1[index]),
                "support": int(support[index]),
                "false_positive_rate": false_positive_rates[index],
            }
            for index, label in enumerate(classes)
        },
        "confusion_matrix": {
            "labels_in_order": classes,
            "values": matrix.astype(int).tolist(),
        },
    }


def _evaluate(
    model: RandomForestClassifier,
    features: pd.DataFrame,
    labels: pd.Series,
    classes: list[str],
) -> dict[str, Any]:
    predictions = model.predict(features)
    return _classification_metrics(labels, predictions, classes)


def train_and_evaluate(
    labels_path: str | Path = DEFAULT_LABELS_PATH,
    *,
    db_path: str | Path = DEFAULT_DB_PATH,
    model_path: str | Path = DEFAULT_MODEL_PATH,
    metrics_path: str | Path = DEFAULT_METRICS_PATH,
    different_seed_labels_path: str | Path | None = None,
    test_size: float = DEFAULT_TEST_SIZE,
    random_state: int = DEFAULT_RANDOM_STATE,
    cv_folds: int = DEFAULT_CV_FOLDS,
    include_isolation_forest: bool = True,
) -> dict[str, Any]:
    """Stratify, cross-validate, test, and save the Random Forest and metrics.

    Optional different-seed labels are evaluated separately after model
    selection and do not enter the train/test split, cross-validation, or fit.
    """
    _validate_training_options(
        test_size=test_size,
        random_state=random_state,
        cv_folds=cv_folds,
    )
    features, labels = _load_dataset(labels_path, db_path)
    class_counts = _class_counts(labels)
    if len(class_counts) < 2:
        raise ValueError("At least two distinct labels are required for classification.")
    if min(class_counts.values()) < 2:
        raise ValueError("Each label needs at least two sessions for stratified splitting.")

    x_train, x_test, y_train, y_test = train_test_split(
        features,
        labels,
        test_size=test_size,
        random_state=random_state,
        stratify=labels,
    )
    minimum_train_class_count = int(y_train.value_counts().min())
    actual_cv_folds = min(cv_folds, minimum_train_class_count)
    if actual_cv_folds < 2:
        raise ValueError("Each training label needs at least two sessions for cross-validation.")

    model = RandomForestClassifier(
        n_estimators=DEFAULT_TREE_COUNT,
        class_weight="balanced",
        random_state=random_state,
        n_jobs=1,
    )
    cv = StratifiedKFold(
        n_splits=actual_cv_folds,
        shuffle=True,
        random_state=random_state,
    )
    cv_results = cross_validate(
        model,
        x_train,
        y_train,
        cv=cv,
        scoring={
            "precision_macro": make_scorer(
                precision_score,
                average="macro",
                zero_division=0,
            ),
            "recall_macro": make_scorer(
                recall_score,
                average="macro",
                zero_division=0,
            ),
            "f1_macro": make_scorer(
                f1_score,
                average="macro",
                zero_division=0,
            ),
        },
        error_score="raise",
    )
    model.fit(x_train, y_train)
    test_metrics = _evaluate(model, x_test, y_test, list(model.classes_))

    metrics: dict[str, Any] = {
        "model": "RandomForestClassifier",
        "features": list(features.columns),
        "label_counts": class_counts,
        "split": {
            "strategy": "stratified train_test_split",
            "test_size": test_size,
            "random_state": random_state,
            "training_samples": int(len(y_train)),
            "test_samples": int(len(y_test)),
        },
        "cross_validation": {
            "strategy": "StratifiedKFold",
            "folds": actual_cv_folds,
            "scoring": "macro average",
            "mean_precision": float(np.mean(cv_results["test_precision_macro"])),
            "std_precision": float(np.std(cv_results["test_precision_macro"])),
            "mean_recall": float(np.mean(cv_results["test_recall_macro"])),
            "std_recall": float(np.std(cv_results["test_recall_macro"])),
            "mean_f1": float(np.mean(cv_results["test_f1_macro"])),
            "std_f1": float(np.std(cv_results["test_f1_macro"])),
        },
        "stratified_test": test_metrics,
    }

    model.fit(features, labels)
    if different_seed_labels_path is not None:
        different_seed_features, different_seed_labels = _load_dataset(
            different_seed_labels_path,
            db_path,
        )
        if set(different_seed_labels.unique()) != set(model.classes_):
            raise ValueError(
                "Different-seed labels must contain the same classes as training."
            )
        metrics["different_seed_evaluation"] = _evaluate(
            model,
            different_seed_features.reindex(columns=features.columns),
            different_seed_labels,
            list(model.classes_),
        )
        metrics["different_seed_evaluation"]["labels_file"] = str(
            different_seed_labels_path
        )

    if include_isolation_forest:
        benign_training_features = x_train.loc[y_train == "benign"]
        if benign_training_features.empty:
            raise ValueError("Isolation Forest baseline requires benign training sessions.")
        isolation_forest = IsolationForest(
            n_estimators=DEFAULT_TREE_COUNT,
            contamination="auto",
            random_state=random_state,
        )
        isolation_forest.fit(benign_training_features)
        baseline_predictions = np.where(
            isolation_forest.predict(x_test) == -1,
            "anomaly",
            "benign",
        )
        binary_test_labels = y_test.map(
            lambda label: "benign" if label == "benign" else "anomaly"
        )
        metrics["isolation_forest_baseline"] = _classification_metrics(
            binary_test_labels,
            baseline_predictions,
            ["benign", "anomaly"],
        )

    model_file = Path(model_path)
    metrics_file = Path(metrics_path)
    model_file.parent.mkdir(parents=True, exist_ok=True)
    metrics_file.parent.mkdir(parents=True, exist_ok=True)
    artifact = {
        "model": model,
        "feature_columns": list(features.columns),
        "classes": list(model.classes_),
    }
    try:
        joblib.dump(artifact, model_file)
        metrics_file.write_text(
            json.dumps(metrics, indent=2, allow_nan=False) + "\n",
            encoding="utf-8",
        )
    except OSError:
        logger.exception("Could not save model or metrics output.")
        raise
    return metrics


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Train and evaluate the honeypot Random Forest model."
    )
    parser.add_argument("--labels", type=Path, default=DEFAULT_LABELS_PATH)
    parser.add_argument("--database", type=Path, default=DEFAULT_DB_PATH)
    parser.add_argument("--model", type=Path, default=DEFAULT_MODEL_PATH)
    parser.add_argument("--metrics", type=Path, default=DEFAULT_METRICS_PATH)
    parser.add_argument(
        "--different-seed-labels",
        type=Path,
        help="separate labels CSV from a simulation run with a different seed",
    )
    parser.add_argument("--random-state", type=int, default=DEFAULT_RANDOM_STATE)
    parser.add_argument("--cv-folds", type=int, default=DEFAULT_CV_FOLDS)
    parser.add_argument("--test-size", type=float, default=DEFAULT_TEST_SIZE)
    parser.add_argument(
        "--no-isolation-forest",
        action="store_true",
        help="skip the optional benign-versus-anomaly baseline",
    )
    args = parser.parse_args()
    metrics = train_and_evaluate(
        args.labels,
        db_path=args.database,
        model_path=args.model,
        metrics_path=args.metrics,
        different_seed_labels_path=args.different_seed_labels,
        random_state=args.random_state,
        cv_folds=args.cv_folds,
        test_size=args.test_size,
        include_isolation_forest=not args.no_isolation_forest,
    )
    print(json.dumps(metrics, indent=2))


if __name__ == "__main__":
    main()
