import sqlite3

import pandas as pd
import pytest

from database.db import create_event, create_session, initialize_database
from features.extractor import FEATURE_COLUMNS, extract_features


def _set_times(db_path, session_id, *, started_at, event_times):
    with sqlite3.connect(db_path) as connection:
        connection.execute(
            "UPDATE sessions SET started_at = ? WHERE id = ?",
            (started_at, session_id),
        )
        for event_id, occurred_at in event_times.items():
            connection.execute(
                "UPDATE events SET occurred_at = ? WHERE id = ?",
                (occurred_at, event_id),
            )


def test_extracts_numeric_features_from_session_events(tmp_path):
    db_path = tmp_path / "features.db"
    initialize_database(db_path)
    session_id = create_session("127.0.0.1", db_path=db_path)
    connection_event = create_event(
        session_id,
        "tcp_connection",
        {"service": "fake_login"},
        db_path=db_path,
    )
    login_event = create_event(
        session_id,
        "tcp_login_attempt",
        {"username": "guest", "password_length": 8},
        db_path=db_path,
    )
    request_event = create_event(
        session_id,
        "http_request",
        {"method": "POST", "path": "/login", "content_type": "form"},
        db_path=db_path,
    )
    web_login_event = create_event(
        session_id,
        "http_login_attempt",
        {"username": "guest", "password_length": 4},
        db_path=db_path,
    )
    error_event = create_event(
        session_id,
        "tcp_protocol_error",
        {"error": "TimeoutError"},
        db_path=db_path,
    )
    _set_times(
        db_path,
        session_id,
        started_at="2026-01-01 00:00:00",
        event_times={
            connection_event: "2026-01-01 00:00:00",
            login_event: "2026-01-01 00:00:10",
            request_event: "2026-01-01 00:00:20",
            web_login_event: "2026-01-01 00:00:25",
            error_event: "2026-01-01 00:01:00",
        },
    )

    result = extract_features(db_path)

    assert isinstance(result, pd.DataFrame)
    assert list(result.columns) == list(FEATURE_COLUMNS)
    assert result.index.name == "session_id"
    assert list(result.index) == [session_id]
    assert all(pd.api.types.is_numeric_dtype(dtype) for dtype in result.dtypes)
    row = result.loc[session_id]
    assert row["event_count"] == 5
    assert row["tcp_connection_count"] == 1
    assert row["http_request_count"] == 1
    assert row["login_attempt_count"] == 2
    assert row["unique_usernames"] == 1
    assert row["unique_paths"] == 1
    assert row["session_duration_seconds"] == 60
    assert row["attempts_per_minute"] == 2
    assert row["payload_length_chars"] == len("guest") + 8 + len("/login") + len("guest") + 4
    assert row["error_count"] == 1
    assert row["error_ratio"] == pytest.approx(0.2)
    assert row["unique_event_types"] == 5


def test_includes_sessions_with_no_events(tmp_path):
    db_path = tmp_path / "empty-session.db"
    initialize_database(db_path)
    session_id = create_session("127.0.0.1", db_path=db_path)

    result = extract_features(db_path)

    assert list(result.index) == [session_id]
    assert (result.loc[session_id] == 0).all()


def test_empty_database_returns_numeric_dataframe(tmp_path):
    db_path = tmp_path / "empty.db"
    initialize_database(db_path)

    result = extract_features(db_path)

    assert result.empty
    assert list(result.columns) == list(FEATURE_COLUMNS)
    assert result.index.name == "session_id"
    assert all(pd.api.types.is_numeric_dtype(dtype) for dtype in result.dtypes)


def test_rejects_malformed_event_json(tmp_path):
    db_path = tmp_path / "malformed.db"
    initialize_database(db_path)
    session_id = create_session("127.0.0.1", db_path=db_path)
    event_id = create_event(session_id, "http_request", db_path=db_path)
    with sqlite3.connect(db_path) as connection:
        connection.execute(
            "UPDATE events SET details = ? WHERE id = ?",
            ("not-json", event_id),
        )

    with pytest.raises(ValueError, match="invalid event details JSON"):
        extract_features(db_path)


def test_rejects_invalid_login_payload_data(tmp_path):
    db_path = tmp_path / "invalid-payload.db"
    initialize_database(db_path)
    session_id = create_session("127.0.0.1", db_path=db_path)
    create_event(
        session_id,
        "tcp_login_attempt",
        {"username": "guest", "password_length": -1},
        db_path=db_path,
    )

    with pytest.raises(ValueError, match="password_length"):
        extract_features(db_path)


def test_missing_database_reports_sqlite_error(tmp_path):
    with pytest.raises(sqlite3.OperationalError, match="no such table"):
        extract_features(tmp_path / "missing.db")


@pytest.mark.parametrize("invalid_path", ["", None, 42])
def test_rejects_invalid_database_path(invalid_path):
    with pytest.raises(ValueError, match="db_path"):
        extract_features(invalid_path)
