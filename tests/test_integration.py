import csv

import joblib
import pandas as pd
from sklearn.ensemble import RandomForestClassifier

from database.db import list_adaptive_actions, list_events, list_sessions
from features.extractor import FEATURE_COLUMNS
from integration.run import load_model_artifact, run_pipeline
from simulator.runner import SimulationConfig


def _save_majority_model(path):
    features = pd.DataFrame(
        [{column: 0.0 for column in FEATURE_COLUMNS} for _ in range(10)],
        columns=FEATURE_COLUMNS,
    )
    labels = ["brute_force"] * 9 + ["benign"]
    model = RandomForestClassifier(n_estimators=5, random_state=1)
    model.fit(features, labels)
    joblib.dump(
        {
            "model": model,
            "feature_columns": list(FEATURE_COLUMNS),
            "classes": list(model.classes_),
        },
        path,
    )


def test_full_local_pipeline_uses_saved_model_for_classification_and_adaptation(
    tmp_path,
):
    db_path = tmp_path / "end-to-end.db"
    labels_path = tmp_path / "ground-truth.csv"
    model_path = tmp_path / "model.joblib"
    _save_majority_model(model_path)
    config = SimulationConfig(
        seed=17,
        min_delay_seconds=0,
        max_delay_seconds=0,
        brute_force_sessions=2,
        port_scan_sessions=2,
        sql_injection_sessions=2,
        directory_probe_sessions=2,
        benign_sessions=2,
        brute_force_attempt_min=5,
        brute_force_attempt_max=8,
        low_and_slow_min_delay_seconds=0,
        low_and_slow_max_delay_seconds=0,
        low_and_slow_probability=0,
    )

    artifact = load_model_artifact(model_path)
    assert artifact["classes"] == ["benign", "brute_force"]

    result = run_pipeline(
        config=config,
        db_path=db_path,
        labels_path=labels_path,
        model_path=model_path,
    )

    assert result.simulated_sessions == 10
    assert result.classified_sessions == 10
    assert result.classifications == {"brute_force": 10}
    assert result.adaptive_actions >= 10
    assert result.alerts == 10
    assert result.dashboard_sessions == 10
    assert result.dashboard_events > 10
    assert labels_path.exists()

    sessions = list_sessions(limit=100, db_path=db_path)
    assert len(sessions) == 10
    all_events = [
        event
        for session in sessions
        for event in list_events(
            session_id=session["id"],
            limit=100,
            db_path=db_path,
        )
    ]
    assert all("label" not in event["details"] for event in all_events)
    with labels_path.open(newline="", encoding="utf-8") as labels_file:
        labels = list(csv.DictReader(labels_file))
    brute_force_ids = {
        int(row["session_id"])
        for row in labels
        if row["label"] == "brute_force"
    }
    brute_force_events = [
        event
        for event in all_events
        if event["session_id"] in brute_force_ids
        and event["event_type"] == "tcp_login_attempt"
    ]
    assert 5 <= len(brute_force_events) <= 100
    assert all(
        5
        <= sum(
            event["session_id"] == session_id
            for event in brute_force_events
        )
        <= 50
        for session_id in brute_force_ids
    )
    assert len({event["details"]["username"] for event in brute_force_events}) > 1
    actions = list_adaptive_actions(limit=100, db_path=db_path)
    observed = [
        action
        for action in actions
        if action["action_type"] == "classification_observed"
    ]
    assert len(observed) == 10
    assert all(action["details"]["classification"] == "brute_force" for action in observed)
    assert len({session["source_ip"] for session in sessions}) >= 3
