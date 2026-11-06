"""Validated, parameterized SQLite operations for honeypot records."""

import ipaddress
import json
import logging
import sqlite3
from contextlib import contextmanager
from pathlib import Path
from typing import Iterator


logger = logging.getLogger(__name__)
DEFAULT_DB_PATH = Path(__file__).resolve().parent.parent / "data" / "honeypot.db"
SCHEMA_PATH = Path(__file__).with_name("schema.sql")
ALLOWED_SEVERITIES = frozenset({"low", "medium", "high", "critical"})
MAX_QUERY_LIMIT = 1000


@contextmanager
def _connection(db_path: str | Path) -> Iterator[sqlite3.Connection]:
    path = _validate_db_path(db_path)
    connection: sqlite3.Connection | None = None
    try:
        connection = sqlite3.connect(path)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys = ON")
        yield connection
        connection.commit()
    except sqlite3.Error:
        if connection is not None:
            connection.rollback()
        logger.exception("SQLite operation failed for database '%s'.", path)
        raise
    finally:
        if connection is not None:
            connection.close()


def _validate_db_path(db_path: str | Path) -> str:
    if not isinstance(db_path, (str, Path)) or not str(db_path).strip():
        raise ValueError("db_path must be a non-empty path.")
    return str(db_path)


def _validate_text(value: str, name: str, *, max_length: int = 4096) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{name} must be a non-empty string.")
    if len(value) > max_length or "\x00" in value:
        raise ValueError(f"{name} must be at most {max_length} characters without NUL.")
    return value.strip()


def _validate_id(value: int, name: str) -> int:
    if type(value) is not int or value < 1:
        raise ValueError(f"{name} must be a positive integer.")
    return value


def _validate_limit(limit: int) -> int:
    if type(limit) is not int or not 1 <= limit <= MAX_QUERY_LIMIT:
        raise ValueError(f"limit must be an integer from 1 through {MAX_QUERY_LIMIT}.")
    return limit


def _validate_offset(offset: int) -> int:
    if type(offset) is not int or offset < 0:
        raise ValueError("offset must be a non-negative integer.")
    return offset


def _serialize_details(details: dict[str, object] | None) -> str:
    if details is None:
        details = {}
    if not isinstance(details, dict):
        raise ValueError("details must be a dictionary.")
    try:
        return json.dumps(details, allow_nan=False)
    except (TypeError, ValueError) as exc:
        raise ValueError("details must contain only JSON-serializable values.") from exc


def _record(row: sqlite3.Row | None) -> dict[str, object] | None:
    if row is None:
        return None
    result = dict(row)
    if "details" in result:
        result["details"] = json.loads(result["details"])
    return result


def _records(rows: list[sqlite3.Row]) -> list[dict[str, object]]:
    records = []
    for row in rows:
        record = dict(row)
        if "details" in record:
            record["details"] = json.loads(record["details"])
        records.append(record)
    return records


def initialize_database(db_path: str | Path = DEFAULT_DB_PATH) -> None:
    """Create the database file and required tables if they do not exist."""
    path = Path(_validate_db_path(db_path))
    path.parent.mkdir(parents=True, exist_ok=True)
    try:
        schema = SCHEMA_PATH.read_text(encoding="utf-8")
    except OSError:
        logger.exception("Unable to read database schema at '%s'.", SCHEMA_PATH)
        raise
    with _connection(path) as connection:
        connection.executescript(schema)


def create_session(
    source_ip: str,
    *,
    db_path: str | Path = DEFAULT_DB_PATH,
) -> int:
    """Insert a session and return its generated ID."""
    source_ip = _validate_text(source_ip, "source_ip", max_length=45)
    try:
        ipaddress.ip_address(source_ip)
    except ValueError as exc:
        raise ValueError("source_ip must be a valid IPv4 or IPv6 address.") from exc
    with _connection(db_path) as connection:
        cursor = connection.execute(
            "INSERT INTO sessions (source_ip) VALUES (?)",
            (source_ip,),
        )
        return cursor.lastrowid


def get_session(
    session_id: int,
    *,
    db_path: str | Path = DEFAULT_DB_PATH,
) -> dict[str, object] | None:
    session_id = _validate_id(session_id, "session_id")
    with _connection(db_path) as connection:
        return _record(
            connection.execute(
                "SELECT id, source_ip, started_at FROM sessions WHERE id = ?",
                (session_id,),
            ).fetchone()
        )


def list_sessions(
    *,
    limit: int = 100,
    offset: int = 0,
    db_path: str | Path = DEFAULT_DB_PATH,
) -> list[dict[str, object]]:
    limit = _validate_limit(limit)
    offset = _validate_offset(offset)
    with _connection(db_path) as connection:
        rows = connection.execute(
            "SELECT id, source_ip, started_at FROM sessions "
            "ORDER BY id DESC LIMIT ? OFFSET ?",
            (limit, offset),
        ).fetchall()
        return _records(rows)


def create_event(
    session_id: int,
    event_type: str,
    details: dict[str, object] | None = None,
    *,
    db_path: str | Path = DEFAULT_DB_PATH,
) -> int:
    session_id = _validate_id(session_id, "session_id")
    event_type = _validate_text(event_type, "event_type", max_length=100)
    details_json = _serialize_details(details)
    with _connection(db_path) as connection:
        cursor = connection.execute(
            "INSERT INTO events (session_id, event_type, details) VALUES (?, ?, ?)",
            (session_id, event_type, details_json),
        )
        return cursor.lastrowid


def get_event(
    event_id: int,
    *,
    db_path: str | Path = DEFAULT_DB_PATH,
) -> dict[str, object] | None:
    event_id = _validate_id(event_id, "event_id")
    with _connection(db_path) as connection:
        return _record(
            connection.execute(
                "SELECT id, session_id, occurred_at, event_type, details "
                "FROM events WHERE id = ?",
                (event_id,),
            ).fetchone()
        )


def list_events(
    *,
    session_id: int | None = None,
    limit: int = 100,
    db_path: str | Path = DEFAULT_DB_PATH,
) -> list[dict[str, object]]:
    limit = _validate_limit(limit)
    if session_id is not None:
        session_id = _validate_id(session_id, "session_id")
        query = (
            "SELECT id, session_id, occurred_at, event_type, details "
            "FROM events WHERE session_id = ? ORDER BY id DESC LIMIT ?"
        )
        parameters = (session_id, limit)
    else:
        query = (
            "SELECT id, session_id, occurred_at, event_type, details "
            "FROM events ORDER BY id DESC LIMIT ?"
        )
        parameters = (limit,)
    with _connection(db_path) as connection:
        return _records(connection.execute(query, parameters).fetchall())


def create_alert(
    session_id: int,
    severity: str,
    message: str,
    *,
    db_path: str | Path = DEFAULT_DB_PATH,
) -> int:
    session_id = _validate_id(session_id, "session_id")
    severity = _validate_text(severity, "severity", max_length=20).lower()
    if severity not in ALLOWED_SEVERITIES:
        raise ValueError("severity must be low, medium, high, or critical.")
    message = _validate_text(message, "message")
    with _connection(db_path) as connection:
        cursor = connection.execute(
            "INSERT INTO alerts (session_id, severity, message) VALUES (?, ?, ?)",
            (session_id, severity, message),
        )
        return cursor.lastrowid


def get_alert(
    alert_id: int,
    *,
    db_path: str | Path = DEFAULT_DB_PATH,
) -> dict[str, object] | None:
    alert_id = _validate_id(alert_id, "alert_id")
    with _connection(db_path) as connection:
        return _record(
            connection.execute(
                "SELECT id, session_id, created_at, severity, message "
                "FROM alerts WHERE id = ?",
                (alert_id,),
            ).fetchone()
        )


def list_alerts(
    *,
    session_id: int | None = None,
    limit: int = 100,
    db_path: str | Path = DEFAULT_DB_PATH,
) -> list[dict[str, object]]:
    limit = _validate_limit(limit)
    if session_id is not None:
        session_id = _validate_id(session_id, "session_id")
        query = (
            "SELECT id, session_id, created_at, severity, message "
            "FROM alerts WHERE session_id = ? ORDER BY id DESC LIMIT ?"
        )
        parameters = (session_id, limit)
    else:
        query = (
            "SELECT id, session_id, created_at, severity, message "
            "FROM alerts ORDER BY id DESC LIMIT ?"
        )
        parameters = (limit,)
    with _connection(db_path) as connection:
        return _records(connection.execute(query, parameters).fetchall())


def create_adaptive_action(
    session_id: int,
    action_type: str,
    details: dict[str, object] | None = None,
    *,
    alert_id: int | None = None,
    outcome: str | None = None,
    db_path: str | Path = DEFAULT_DB_PATH,
) -> int:
    session_id = _validate_id(session_id, "session_id")
    action_type = _validate_text(action_type, "action_type", max_length=100)
    details_json = _serialize_details(details)
    if alert_id is not None:
        alert_id = _validate_id(alert_id, "alert_id")
    if outcome is not None:
        outcome = _validate_text(outcome, "outcome")
    with _connection(db_path) as connection:
        cursor = connection.execute(
            "INSERT INTO adaptive_actions "
            "(session_id, alert_id, action_type, details, outcome) "
            "VALUES (?, ?, ?, ?, ?)",
            (session_id, alert_id, action_type, details_json, outcome),
        )
        return cursor.lastrowid


def get_adaptive_action(
    action_id: int,
    *,
    db_path: str | Path = DEFAULT_DB_PATH,
) -> dict[str, object] | None:
    action_id = _validate_id(action_id, "action_id")
    with _connection(db_path) as connection:
        return _record(
            connection.execute(
                "SELECT id, session_id, alert_id, created_at, action_type, details, outcome "
                "FROM adaptive_actions WHERE id = ?",
                (action_id,),
            ).fetchone()
        )


def list_adaptive_actions(
    *,
    session_id: int | None = None,
    limit: int = 100,
    offset: int = 0,
    db_path: str | Path = DEFAULT_DB_PATH,
) -> list[dict[str, object]]:
    limit = _validate_limit(limit)
    offset = _validate_offset(offset)
    if session_id is not None:
        session_id = _validate_id(session_id, "session_id")
        query = (
            "SELECT id, session_id, alert_id, created_at, action_type, details, outcome "
            "FROM adaptive_actions WHERE session_id = ? "
            "ORDER BY id DESC LIMIT ? OFFSET ?"
        )
        parameters = (session_id, limit, offset)
    else:
        query = (
            "SELECT id, session_id, alert_id, created_at, action_type, details, outcome "
            "FROM adaptive_actions ORDER BY id DESC LIMIT ? OFFSET ?"
        )
        parameters = (limit, offset)
    with _connection(db_path) as connection:
        return _records(connection.execute(query, parameters).fetchall())
