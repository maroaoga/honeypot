import sqlite3

import pytest

from database.db import (
    create_adaptive_action,
    create_alert,
    create_event,
    create_session,
    get_adaptive_action,
    get_alert,
    get_event,
    get_session,
    initialize_database,
    list_adaptive_actions,
    list_alerts,
    list_events,
    list_sessions,
)


@pytest.fixture
def db_path(tmp_path):
    path = tmp_path / "honeypot.db"
    initialize_database(path)
    return path


def test_initialize_database_is_repeatable(db_path):
    initialize_database(db_path)
    assert list_sessions(db_path=db_path) == []


def test_new_database_timestamps_include_subsecond_precision(db_path):
    session_id = create_session("127.0.0.1", db_path=db_path)
    event_id = create_event(session_id, "connection", db_path=db_path)

    session = get_session(session_id, db_path=db_path)
    event = get_event(event_id, db_path=db_path)

    assert "." in session["started_at"]
    assert "." in event["occurred_at"]


def test_create_and_query_all_record_types(db_path):
    session_id = create_session("127.0.0.1", db_path=db_path)
    event_id = create_event(
        session_id,
        "login_attempt",
        {"username": "guest", "attempt": 1},
        db_path=db_path,
    )
    alert_id = create_alert(session_id, "HIGH", "Repeated login failures", db_path=db_path)
    action_id = create_adaptive_action(
        session_id,
        "increase_delay",
        {"seconds": 2},
        alert_id=alert_id,
        outcome="applied",
        db_path=db_path,
    )

    assert get_session(session_id, db_path=db_path)["source_ip"] == "127.0.0.1"
    assert get_event(event_id, db_path=db_path)["details"] == {
        "username": "guest",
        "attempt": 1,
    }
    assert get_alert(alert_id, db_path=db_path)["severity"] == "high"
    assert get_adaptive_action(action_id, db_path=db_path)["outcome"] == "applied"
    assert [row["id"] for row in list_events(session_id=session_id, db_path=db_path)] == [
        event_id
    ]
    assert [row["id"] for row in list_alerts(session_id=session_id, db_path=db_path)] == [
        alert_id
    ]
    assert [
        row["id"]
        for row in list_adaptive_actions(session_id=session_id, db_path=db_path)
    ] == [action_id]
    assert [row["id"] for row in list_sessions(db_path=db_path)] == [session_id]


def test_queries_return_none_for_missing_ids(db_path):
    assert get_session(99, db_path=db_path) is None
    assert get_event(99, db_path=db_path) is None
    assert get_alert(99, db_path=db_path) is None
    assert get_adaptive_action(99, db_path=db_path) is None


def test_queries_can_filter_by_session_and_limit(db_path):
    first_session = create_session("127.0.0.1", db_path=db_path)
    second_session = create_session("::1", db_path=db_path)
    create_event(first_session, "first", db_path=db_path)
    create_event(second_session, "second", db_path=db_path)

    assert len(list_events(session_id=first_session, db_path=db_path)) == 1
    assert len(list_events(limit=1, db_path=db_path)) == 1


def test_session_and_action_queries_support_parameterized_offsets(db_path):
    session_ids = [
        create_session("127.0.0.1", db_path=db_path)
        for _ in range(3)
    ]
    for session_id in session_ids:
        create_adaptive_action(
            session_id,
            "classification_observed",
            db_path=db_path,
        )

    assert [
        row["id"] for row in list_sessions(limit=2, offset=1, db_path=db_path)
    ] == session_ids[1::-1]
    assert [
        row["session_id"]
        for row in list_adaptive_actions(limit=2, offset=1, db_path=db_path)
    ] == session_ids[1::-1]


def test_parameterized_values_are_stored_as_data(db_path):
    session_id = create_session("127.0.0.1", db_path=db_path)
    event_id = create_event(
        session_id,
        "login'); DROP TABLE sessions; --",
        db_path=db_path,
    )

    assert get_event(event_id, db_path=db_path)["event_type"] == (
        "login'); DROP TABLE sessions; --"
    )
    assert get_session(session_id, db_path=db_path) is not None


@pytest.mark.parametrize(
    ("operation", "message"),
    [
        (lambda path: create_session("not-an-ip", db_path=path), "valid IPv4 or IPv6"),
        (lambda path: create_session("", db_path=path), "source_ip"),
        (lambda path: create_event(0, "test", db_path=path), "session_id"),
        (lambda path: create_event(1, "", db_path=path), "event_type"),
        (
            lambda path: create_event(1, "test", {"bad": object()}, db_path=path),
            "JSON-serializable",
        ),
        (lambda path: create_alert(1, "urgent", "message", db_path=path), "severity"),
        (lambda path: create_alert(1, "high", "", db_path=path), "message"),
        (lambda path: create_adaptive_action(1, "", db_path=path), "action_type"),
        (lambda path: get_session(True, db_path=path), "session_id"),
        (lambda path: list_events(limit=0, db_path=path), "limit"),
        (lambda path: list_sessions(offset=-1, db_path=path), "offset"),
    ],
)
def test_rejects_invalid_input(db_path, operation, message):
    with pytest.raises(ValueError, match=message):
        operation(db_path)


def test_foreign_keys_reject_unknown_session(db_path):
    with pytest.raises(sqlite3.IntegrityError, match="FOREIGN KEY constraint failed"):
        create_event(999, "orphan", db_path=db_path)
