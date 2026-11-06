from adaptive.rules import get_source_controls
from database.db import list_adaptive_actions, list_events, list_sessions
from integration.run import classify_session_events, run_pipeline
from simulator.runner import SimulationConfig


def test_full_local_pipeline_simulates_classifies_adapts_and_populates_dashboard(
    tmp_path,
):
    db_path = tmp_path / "end-to-end.db"
    labels_path = tmp_path / "ground-truth.csv"
    config = SimulationConfig(
        seed=17,
        min_delay_seconds=0,
        max_delay_seconds=0,
        brute_force_attempts=2,
        port_scan_probes=2,
        sql_injection_probes=2,
        directory_probes=2,
        benign_sessions=2,
    )

    result = run_pipeline(
        config=config,
        db_path=db_path,
        labels_path=labels_path,
    )

    assert result.simulated_sessions == 10
    assert result.classified_sessions == 10
    assert result.classifications == {
        "benign": 2,
        "brute_force": 2,
        "directory_probe": 2,
        "port_scan": 2,
        "sql_injection": 2,
    }
    assert result.adaptive_actions >= 10
    assert result.alerts >= 8
    assert result.dashboard_sessions == 10
    assert result.dashboard_events >= 10
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
    assert classify_session_events(all_events[:1])[0] in {
        "brute_force",
        "port_scan",
        "sql_injection",
        "directory_probe",
        "benign",
    }
    assert all("label" not in event["details"] for event in all_events)
    actions = list_adaptive_actions(limit=100, db_path=db_path)
    assert any(action["action_type"] == "threshold_adjusted" for action in actions)
    assert any(action["action_type"] == "scan_banner_changed" for action in actions)
    assert get_source_controls("127.0.0.1", db_path=db_path).rate_limited is True


def test_event_classifier_uses_events_not_external_labels():
    classification, confidence = classify_session_events(
        [
            {
                "event_type": "http_login_attempt",
                "details": {"username": "admin' OR '1'='1"},
            },
            {
                "event_type": "http_request",
                "details": {"path": "/login", "method": "POST"},
            },
        ]
    )

    assert classification == "sql_injection"
    assert confidence == 0.95
