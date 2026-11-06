import csv

from database.db import create_event, create_session, initialize_database
from scripts.run_experiment import _database_summary


def test_experiment_summary_reports_labeled_sessions_events_and_attempt_bounds(
    tmp_path,
):
    database = tmp_path / "experiment.db"
    labels_path = tmp_path / "labels.csv"
    config_path = tmp_path / "simulator.yaml"
    initialize_database(database)
    labels = []
    for label, source_ip in (
        ("benign", "127.0.0.1"),
        ("brute_force", "127.0.0.2"),
        ("brute_force", "127.0.0.3"),
    ):
        session_id = create_session(source_ip, db_path=database)
        if label == "brute_force":
            for attempt in range(5):
                create_event(
                    session_id,
                    "tcp_login_attempt",
                    {"username": f"user-{attempt}", "password_length": 8},
                    db_path=database,
                )
        else:
            create_event(
                session_id,
                "http_login_attempt",
                {"username": "alcie", "password_length": 128},
                db_path=database,
            )
        labels.append((session_id, label))
    with labels_path.open("w", newline="", encoding="utf-8") as labels_file:
        writer = csv.writer(labels_file)
        writer.writerow(("session_id", "label"))
        writer.writerows(labels)
    config_path.write_text(
        "seed: 123\n"
        "timing:\n  min_delay_seconds: 0\n  max_delay_seconds: 0\n"
        "volumes: {}\n",
        encoding="utf-8",
    )

    summary = _database_summary(
        database,
        labels_path,
        config_path,
        date_generated="2026-01-01T00:00:00+00:00",
    )

    assert summary["total_sessions"] == 3
    assert summary["session_counts_by_class"] == {"benign": 1, "brute_force": 2}
    assert summary["class_percentages"] == {
        "benign": 100 / 3,
        "brute_force": 200 / 3,
    }
    assert summary["event_counts_by_class"] == {"benign": 1, "brute_force": 10}
    assert summary["total_events"] == 11
    assert summary["unique_loopback_source_ips"] == 3
    assert summary["brute_force_attempts_per_session"] == {
        "minimum": 5,
        "mean": 5.0,
        "maximum": 5,
    }
