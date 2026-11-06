"""Turn stored session events into numeric, label-free model features."""

import json
import logging
import sqlite3
from collections import Counter, deque
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import pandas as pd

from database.db import DEFAULT_DB_PATH


logger = logging.getLogger(__name__)
FEATURE_COLUMNS = (
    "event_count",
    "tcp_connection_count",
    "http_request_count",
    "login_attempt_count",
    "unique_usernames",
    "unique_paths",
    "session_duration_seconds",
    "attempts_per_minute",
    "payload_length_chars",
    "error_count",
    "error_ratio",
    "unique_event_types",
    "source_attempts_60s",
    "source_distinct_usernames_60s",
    "source_request_rate_per_second_60s",
)
ERROR_EVENT_TYPES = frozenset({"tcp_protocol_error", "http_error"})
LOGIN_EVENT_TYPES = frozenset({"tcp_login_attempt", "http_login_attempt"})


def _validate_db_path(db_path: str | Path) -> str:
    if not isinstance(db_path, (str, Path)) or not str(db_path).strip():
        raise ValueError("db_path must be a non-empty path.")
    return str(db_path)


def _parse_timestamp(value: str, *, session_id: int, field: str) -> datetime:
    try:
        parsed = datetime.fromisoformat(value)
    except (TypeError, ValueError) as exc:
        raise ValueError(
            f"Session {session_id} has an invalid {field} timestamp."
        ) from exc
    if parsed.tzinfo is None:
        return parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def _event_payload_length(event_type: str, details: dict[str, Any]) -> int:
    payload_length = 0
    if event_type in LOGIN_EVENT_TYPES:
        username = details.get("username", "")
        password_length = details.get("password_length", 0)
        if not isinstance(username, str):
            raise ValueError("Login event username must be a string.")
        if type(password_length) is not int or password_length < 0:
            raise ValueError("Login event password_length must be a non-negative integer.")
        payload_length += len(username) + password_length
    if event_type == "http_request":
        path = details.get("path", "")
        if not isinstance(path, str):
            raise ValueError("HTTP request path must be a string.")
        payload_length += len(path)
    return payload_length


def _session_features(
    session_id: int,
    started_at: str,
    events: list[tuple[str, str, dict[str, Any]]],
) -> dict[str, int | float]:
    usernames: set[str] = set()
    paths: set[str] = set()
    event_types: set[str] = set()
    payload_length = 0
    error_count = 0
    timestamps = [_parse_timestamp(started_at, session_id=session_id, field="started_at")]
    tcp_connection_count = 0
    http_request_count = 0
    login_attempt_count = 0

    for event_type, occurred_at, details in events:
        if not isinstance(event_type, str) or not event_type:
            raise ValueError(f"Session {session_id} contains an invalid event type.")
        if not isinstance(details, dict):
            raise ValueError(
                f"Session {session_id} contains non-object event details."
            )

        timestamps.append(
            _parse_timestamp(occurred_at, session_id=session_id, field="event")
        )
        event_types.add(event_type)
        tcp_connection_count += event_type == "tcp_connection"
        http_request_count += event_type == "http_request"
        login_attempt_count += event_type in LOGIN_EVENT_TYPES
        error_count += event_type in ERROR_EVENT_TYPES
        payload_length += _event_payload_length(event_type, details)

        if event_type in LOGIN_EVENT_TYPES and "username" in details:
            username = details["username"]
            if not isinstance(username, str):
                raise ValueError("Login event username must be a string.")
            usernames.add(username)
        if event_type == "http_request" and "path" in details:
            path = details["path"]
            if not isinstance(path, str):
                raise ValueError("HTTP request path must be a string.")
            paths.add(path)

    duration_seconds = max(
        0.0,
        (max(timestamps) - min(timestamps)).total_seconds(),
    )
    attempts_per_minute = login_attempt_count * 60 / max(duration_seconds, 1.0)
    total_events = len(events)

    return {
        "event_count": total_events,
        "tcp_connection_count": tcp_connection_count,
        "http_request_count": http_request_count,
        "login_attempt_count": login_attempt_count,
        "unique_usernames": len(usernames),
        "unique_paths": len(paths),
        "session_duration_seconds": duration_seconds,
        "attempts_per_minute": attempts_per_minute,
        "payload_length_chars": payload_length,
        "error_count": error_count,
        "error_ratio": error_count / total_events if total_events else 0.0,
        "unique_event_types": len(event_types),
    }


def _source_window_features(
    sessions: dict[
        int,
        tuple[str, str, list[tuple[int, str, str, dict[str, Any]]]],
    ],
) -> dict[int, dict[str, int | float]]:
    source_events: dict[str, list[tuple[datetime, int, str, dict[str, Any]]]] = {}
    session_anchors: dict[int, tuple[str, datetime, int]] = {}

    for session_id, (started_at, source_ip, events) in sessions.items():
        anchor = (
            _parse_timestamp(started_at, session_id=session_id, field="started_at"),
            0,
        )
        for event_id, event_type, occurred_at, details in events:
            timestamp = _parse_timestamp(
                occurred_at,
                session_id=session_id,
                field="event",
            )
            source_events.setdefault(source_ip, []).append(
                (timestamp, event_id, event_type, details)
            )
            anchor = max(anchor, (timestamp, event_id))
        session_anchors[session_id] = (source_ip, anchor[0], anchor[1])

    output: dict[int, dict[str, int | float]] = {}
    for source_ip, events in source_events.items():
        events.sort(key=lambda event: (event[0], event[1]))
        anchors = sorted(
            (
                (timestamp, event_id, session_id)
                for session_id, (ip, timestamp, event_id) in session_anchors.items()
                if ip == source_ip
            ),
            key=lambda anchor: (anchor[0], anchor[1]),
        )
        active: deque[tuple[datetime, int, str, str | None]] = deque()
        username_counts: Counter[str] = Counter()
        login_attempts = 0
        requests = 0
        next_event = 0

        for anchor_time, anchor_event_id, session_id in anchors:
            while next_event < len(events) and (
                events[next_event][0], events[next_event][1]
            ) <= (anchor_time, anchor_event_id):
                event_time, event_id, event_type, details = events[next_event]
                username = None
                if event_type in LOGIN_EVENT_TYPES:
                    login_attempts += 1
                    value = details.get("username")
                    if isinstance(value, str):
                        username = value
                        username_counts[username] += 1
                if event_type in {"tcp_connection", "http_request"}:
                    requests += 1
                active.append((event_time, event_id, event_type, username))
                next_event += 1

            cutoff = anchor_time.timestamp() - 60
            while active and active[0][0].timestamp() < cutoff:
                _, _, event_type, username = active.popleft()
                if event_type in LOGIN_EVENT_TYPES:
                    login_attempts -= 1
                if event_type in {"tcp_connection", "http_request"}:
                    requests -= 1
                if username is not None:
                    username_counts[username] -= 1
                    if username_counts[username] == 0:
                        del username_counts[username]

            output[session_id] = {
                "source_attempts_60s": login_attempts,
                "source_distinct_usernames_60s": len(username_counts),
                "source_request_rate_per_second_60s": requests / 60,
            }

    for session_id, (source_ip, anchor_time, _) in session_anchors.items():
        if session_id not in output:
            output[session_id] = {
                "source_attempts_60s": 0,
                "source_distinct_usernames_60s": 0,
                "source_request_rate_per_second_60s": 0.0,
            }
    return output


def extract_features(db_path: str | Path = DEFAULT_DB_PATH) -> pd.DataFrame:
    """Return one numeric feature row per session, indexed by session ID.

    Labels and source IP addresses are intentionally not selected or emitted.
    """
    path = _validate_db_path(db_path)
    query = (
        "SELECT s.id AS session_id, s.started_at, s.source_ip, "
        "e.id AS event_id, e.event_type, e.occurred_at, e.details "
        "FROM sessions AS s "
        "LEFT JOIN events AS e ON e.session_id = s.id "
        "ORDER BY s.id, e.id"
    )
    sessions: dict[
        int,
        tuple[str, str, list[tuple[int, str, str, dict[str, Any]]]],
    ] = {}
    try:
        with sqlite3.connect(path) as connection:
            rows = connection.execute(query).fetchall()
    except sqlite3.Error:
        logger.exception("Could not read sessions for feature extraction from '%s'.", path)
        raise

    for (
        session_id,
        started_at,
        source_ip,
        event_id,
        event_type,
        occurred_at,
        details_json,
    ) in rows:
        if session_id not in sessions:
            sessions[session_id] = (started_at, source_ip, [])
        if event_type is None:
            continue
        try:
            details = json.loads(details_json)
        except (json.JSONDecodeError, TypeError) as exc:
            raise ValueError(
                f"Session {session_id} contains invalid event details JSON."
            ) from exc
        sessions[session_id][2].append((event_id, event_type, occurred_at, details))

    source_features = _source_window_features(sessions)

    records = [
        {
            "session_id": session_id,
            **_session_features(
                session_id,
                started_at,
                [
                    (event_type, occurred_at, details)
                    for _, event_type, occurred_at, details in events
                ],
            ),
            **source_features[session_id],
        }
        for session_id, (started_at, _, events) in sessions.items()
    ]
    if not records:
        return pd.DataFrame(
            columns=FEATURE_COLUMNS,
            index=pd.Index([], name="session_id", dtype="int64"),
        ).astype(
            {
                "event_count": "int64",
                "tcp_connection_count": "int64",
                "http_request_count": "int64",
                "login_attempt_count": "int64",
                "unique_usernames": "int64",
                "unique_paths": "int64",
                "session_duration_seconds": "float64",
                "attempts_per_minute": "float64",
                "payload_length_chars": "int64",
                "error_count": "int64",
                "error_ratio": "float64",
                "unique_event_types": "int64",
                "source_attempts_60s": "int64",
                "source_distinct_usernames_60s": "int64",
                "source_request_rate_per_second_60s": "float64",
            }
        )
    return pd.DataFrame.from_records(records).set_index("session_id")[list(FEATURE_COLUMNS)]
