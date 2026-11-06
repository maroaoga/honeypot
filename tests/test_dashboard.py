import sqlite3
from datetime import date
from pathlib import Path

import pandas as pd
import pytest
from streamlit.testing.v1 import AppTest

from dashboard.data import DashboardDatabaseError, load_dashboard_data
from database.db import create_adaptive_action, create_alert, create_event, create_session, initialize_database


@pytest.fixture
def dashboard_db(tmp_path):
    path = tmp_path / "dashboard.db"
    initialize_database(path)
    sessions = []
    for source_ip, started_at in (
        ("192.0.2.10", "2026-11-06 09:00:00"),
        ("192.0.2.10", "2026-11-06 10:00:00"),
        ("192.0.2.20", "2026-11-05 11:00:00"),
    ):
        session_id = create_session(source_ip, db_path=path)
        with sqlite3.connect(path) as connection:
            connection.execute(
                "UPDATE sessions SET started_at = ? WHERE id = ?",
                (started_at, session_id),
            )
        sessions.append(session_id)
    return path, sessions


def test_loads_dashboard_aggregates_and_events_from_database(dashboard_db):
    db_path, sessions = dashboard_db
    event_id = create_event(
        sessions[0],
        "http_login_attempt",
        {"username": "admin", "password_length": 8},
        db_path=db_path,
    )
    create_adaptive_action(
        sessions[0],
        "classification_observed",
        {
            "classification": "brute_force",
            "confidence": 0.95,
            "malicious": True,
            "source_ip": "192.0.2.10",
        },
        db_path=db_path,
    )
    create_alert(
        sessions[0],
        "high",
        "Repeated login attempts",
        db_path=db_path,
    )
    create_event(
        sessions[1],
        "http_request",
        {"method": "GET", "path": "/"},
        db_path=db_path,
    )

    data = load_dashboard_data(
        db_path,
        start_date=date(2026, 11, 6),
        end_date=date(2026, 11, 6),
    )

    assert data["summary"] == {
        "sessions": 2,
        "events": 2,
        "alerts": 1,
        "malicious_classifications": 1,
        "sources": 1,
    }
    assert data["classifications"].to_dict("records") == [
        {"classification": "brute_force", "count": 1}
    ]
    assert data["sources"].iloc[0].to_dict() == {
        "source_ip": "192.0.2.10",
        "session_count": 2,
        "event_count": 2,
    }
    login_event = data["events"].set_index("event_type").loc["http_login_attempt"]
    assert login_event["classification"] == "brute_force"
    assert login_event["severity"] == "high"
    assert data["alerts"].iloc[0]["message"] == "Repeated login attempts"
    assert "label" not in data["events"].columns
    assert event_id > 0


def test_applies_date_classification_and_severity_filters(dashboard_db):
    db_path, sessions = dashboard_db
    create_event(sessions[0], "login", {"username": "admin"}, db_path=db_path)
    create_adaptive_action(
        sessions[0],
        "classification_observed",
        {"classification": "brute_force", "malicious": True},
        db_path=db_path,
    )
    create_alert(sessions[0], "high", "High alert", db_path=db_path)
    create_event(sessions[2], "login", {"username": "guest"}, db_path=db_path)

    filtered = load_dashboard_data(
        db_path,
        start_date=date(2026, 11, 6),
        end_date=date(2026, 11, 6),
        classification="brute_force",
        severity="high",
    )

    assert len(filtered["events"]) == 1
    assert filtered["events"].iloc[0]["classification"] == "brute_force"
    assert filtered["events"].iloc[0]["severity"] == "high"
    assert len(filtered["alerts"]) == 1


def test_untrusted_filter_values_are_bound_as_data(dashboard_db):
    db_path, _ = dashboard_db

    result = load_dashboard_data(
        db_path,
        start_date=date(2026, 11, 6),
        end_date=date(2026, 11, 6),
        classification="' OR 1=1 --",
        severity="high' OR '1'='1",
    )

    assert result["events"].empty
    assert result["alerts"].empty


def test_empty_database_returns_empty_frames_and_zero_counts(tmp_path):
    db_path = tmp_path / "empty.db"
    initialize_database(db_path)

    data = load_dashboard_data(
        db_path,
        start_date=date.today() - pd.Timedelta(days=1),
        end_date=date.today(),
    )

    assert all(value == 0 for value in data["summary"].values())
    assert data["events"].empty
    assert data["alerts"].empty
    assert data["timeline"].empty
    assert data["classifications"].empty
    assert data["sources"].empty


def test_read_only_dashboard_does_not_create_database(tmp_path):
    db_path = tmp_path / "does-not-exist.db"

    with pytest.raises(DashboardDatabaseError, match="Database not found"):
        load_dashboard_data(
            db_path,
            start_date=date.today(),
            end_date=date.today(),
        )

    assert not db_path.exists()


@pytest.mark.parametrize(
    ("start_date", "end_date", "message"),
    [
        (date(2026, 11, 7), date(2026, 11, 6), "cannot be before"),
        ("2026-11-06", date(2026, 11, 6), "start_date"),
    ],
)
def test_rejects_invalid_date_range(tmp_path, start_date, end_date, message):
    db_path = tmp_path / "dates.db"
    initialize_database(db_path)

    with pytest.raises(ValueError, match=message):
        load_dashboard_data(db_path, start_date=start_date, end_date=end_date)


def test_dashboard_streamlit_empty_state_renders_without_errors(tmp_path, monkeypatch):
    db_path = tmp_path / "empty.db"
    initialize_database(db_path)
    monkeypatch.setenv("HONEYPOT_DB_PATH", str(db_path))

    app_path = Path(__file__).resolve().parents[1] / "dashboard" / "app.py"
    app = AppTest.from_file(app_path).run()

    assert not app.exception
    assert any("No activity yet" in item.value for item in app.subheader)
    assert len(app.metric) == 5


def test_dashboard_streamlit_renders_and_filters_populated_database(
    tmp_path,
    monkeypatch,
):
    db_path = tmp_path / "populated.db"
    initialize_database(db_path)
    session_id = create_session("192.0.2.30", db_path=db_path)
    create_event(session_id, "http_login_attempt", {"username": "admin"}, db_path=db_path)
    create_adaptive_action(
        session_id,
        "classification_observed",
        {
            "classification": "brute_force",
            "confidence": 0.9,
            "malicious": True,
            "source_ip": "192.0.2.30",
        },
        db_path=db_path,
    )
    create_alert(session_id, "high", "Repeated logins", db_path=db_path)
    monkeypatch.setenv("HONEYPOT_DB_PATH", str(db_path))
    app_path = Path(__file__).resolve().parents[1] / "dashboard" / "app.py"

    app = AppTest.from_file(app_path).run()

    assert not app.exception
    assert len(app.metric) == 5
    assert app.metric[1].value == "1"
    app.selectbox(key="classification").select("brute_force").run()

    assert not app.exception
    event_table = app.dataframe[-1].value
    assert len(event_table) == 1
    assert event_table.iloc[0]["classification"] == "brute_force"
