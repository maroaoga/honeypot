"""Read-only, parameterized dashboard queries over the honeypot database."""

import json
import logging
import sqlite3
from datetime import date, datetime, time, timedelta
from pathlib import Path
from typing import Any

import pandas as pd

from database.db import DEFAULT_DB_PATH


logger = logging.getLogger(__name__)
EVENT_COLUMNS = (
    "occurred_at",
    "source_ip",
    "event_type",
    "classification",
    "severity",
    "details",
)
ALERT_COLUMNS = ("created_at", "source_ip", "severity", "message")
TIMELINE_COLUMNS = ("hour", "observed_events", "malicious_classifications")
CLASSIFICATION_COLUMNS = ("classification", "count")
SOURCE_COLUMNS = ("source_ip", "session_count", "event_count")
REQUIRED_TABLES = frozenset({"sessions", "events", "alerts", "adaptive_actions"})


class DashboardDatabaseError(RuntimeError):
    """Raised when the dashboard database is missing or not initialized."""


def _validate_date_range(start_date: date, end_date: date) -> tuple[str, str]:
    if not isinstance(start_date, date) or isinstance(start_date, datetime):
        raise ValueError("start_date must be a date.")
    if not isinstance(end_date, date) or isinstance(end_date, datetime):
        raise ValueError("end_date must be a date.")
    if end_date < start_date:
        raise ValueError("end_date cannot be before start_date.")
    start = datetime.combine(start_date, time.min).strftime("%Y-%m-%d %H:%M:%S")
    end = datetime.combine(end_date + timedelta(days=1), time.min).strftime(
        "%Y-%m-%d %H:%M:%S"
    )
    return start, end


def _empty_frame(columns: tuple[str, ...]) -> pd.DataFrame:
    return pd.DataFrame(columns=columns)


def _read_only_connection(db_path: str | Path) -> sqlite3.Connection:
    if not isinstance(db_path, (str, Path)) or not str(db_path).strip():
        raise ValueError("db_path must be a non-empty path.")
    path = Path(db_path).expanduser().resolve()
    if not path.is_file():
        raise DashboardDatabaseError(
            f"Database not found at '{path}'. Initialize it with "
            "'python -m database.init_db'."
        )
    try:
        connection = sqlite3.connect(f"{path.as_uri()}?mode=ro", uri=True)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA query_only = ON")
        existing_tables = {
            row["name"]
            for row in connection.execute(
                "SELECT name FROM sqlite_master WHERE type = ?",
                ("table",),
            )
        }
        missing_tables = REQUIRED_TABLES - existing_tables
        if missing_tables:
            connection.close()
            raise DashboardDatabaseError(
                "Database is missing required tables: "
                + ", ".join(sorted(missing_tables))
                + ". Initialize it with 'python -m database.init_db'."
            )
        return connection
    except sqlite3.Error:
        logger.exception("Could not open dashboard database '%s' read-only.", path)
        raise


def _fetch_dataframe(
    connection: sqlite3.Connection,
    query: str,
    parameters: tuple[Any, ...] = (),
) -> pd.DataFrame:
    return pd.read_sql_query(query, connection, params=parameters)


def load_dashboard_data(
    db_path: str | Path = DEFAULT_DB_PATH,
    *,
    start_date: date,
    end_date: date,
    classification: str | None = None,
    severity: str | None = None,
) -> dict[str, Any]:
    """Load date-filtered dashboard data without writing to the database.

    The label CSV and model artifacts are never read. Classification values
    come only from recorded ``classification_observed`` adaptive actions.
    """
    start, end = _validate_date_range(start_date, end_date)
    if classification is not None and (
        not isinstance(classification, str) or not classification.strip()
    ):
        raise ValueError("classification must be a non-empty string or None.")
    if severity is not None and (
        not isinstance(severity, str) or not severity.strip()
    ):
        raise ValueError("severity must be a non-empty string or None.")

    connection = _read_only_connection(db_path)
    try:
        summary_row = connection.execute(
            "SELECT "
            "(SELECT COUNT(*) FROM sessions "
            " WHERE started_at >= ? AND started_at < ?) AS sessions, "
            "(SELECT COUNT(*) FROM events "
            " WHERE occurred_at >= ? AND occurred_at < ?) AS events, "
            "(SELECT COUNT(*) FROM alerts "
            " WHERE created_at >= ? AND created_at < ?) AS alerts, "
            "(SELECT COUNT(*) FROM adaptive_actions "
            " WHERE created_at >= ? AND created_at < ? "
            " AND action_type = ? AND json_extract(details, '$.malicious') = 1) "
            " AS malicious_classifications, "
            "(SELECT COUNT(DISTINCT source_ip) FROM sessions "
            " WHERE started_at >= ? AND started_at < ?) AS sources",
            (
                start,
                end,
                start,
                end,
                start,
                end,
                start,
                end,
                "classification_observed",
                start,
                end,
            ),
        ).fetchone()
        summary = {key: int(summary_row[key]) for key in summary_row.keys()}

        timeline = _fetch_dataframe(
            connection,
            "WITH activity AS ("
            " SELECT strftime('%Y-%m-%d %H:00:00', occurred_at) AS hour, "
            "        COUNT(*) AS observed_events, 0 AS malicious_classifications "
            " FROM events WHERE occurred_at >= ? AND occurred_at < ? GROUP BY hour "
            " UNION ALL "
            " SELECT strftime('%Y-%m-%d %H:00:00', created_at) AS hour, "
            "        0 AS observed_events, COUNT(*) AS malicious_classifications "
            " FROM adaptive_actions "
            " WHERE created_at >= ? AND created_at < ? "
            "   AND action_type = ? AND json_extract(details, '$.malicious') = 1 "
            " GROUP BY hour"
            ") SELECT hour, SUM(observed_events) AS observed_events, "
            "SUM(malicious_classifications) AS malicious_classifications "
            "FROM activity GROUP BY hour ORDER BY hour",
            (start, end, start, end, "classification_observed"),
        )
        for column in TIMELINE_COLUMNS[1:]:
            if column not in timeline:
                timeline[column] = pd.Series(dtype="int64")
        if timeline.empty:
            timeline = _empty_frame(TIMELINE_COLUMNS)

        classifications = _fetch_dataframe(
            connection,
            "SELECT json_extract(details, '$.classification') AS classification, "
            "COUNT(*) AS count FROM adaptive_actions "
            "WHERE created_at >= ? AND created_at < ? "
            "AND action_type = ? "
            "AND json_type(details, '$.classification') = 'text' "
            "GROUP BY classification ORDER BY count DESC, classification",
            (start, end, "classification_observed"),
        )
        if classifications.empty:
            classifications = _empty_frame(CLASSIFICATION_COLUMNS)

        sources = _fetch_dataframe(
            connection,
            "SELECT s.source_ip, COUNT(DISTINCT s.id) AS session_count, "
            "COUNT(e.id) AS event_count "
            "FROM sessions AS s LEFT JOIN events AS e "
            "ON e.session_id = s.id AND e.occurred_at >= ? AND e.occurred_at < ? "
            "WHERE s.started_at >= ? AND s.started_at < ? "
            "GROUP BY s.source_ip ORDER BY session_count DESC, event_count DESC, "
            "s.source_ip LIMIT ?",
            (start, end, start, end, 10),
        )
        if sources.empty:
            sources = _empty_frame(SOURCE_COLUMNS)

        classification_expression = (
            "COALESCE((SELECT json_extract(aa.details, '$.classification') "
            "FROM adaptive_actions AS aa "
            "WHERE aa.session_id = s.id "
            "AND aa.action_type = 'classification_observed' "
            "AND json_type(aa.details, '$.classification') = 'text' "
            "ORDER BY aa.id DESC LIMIT 1), 'Unclassified')"
        )
        severity_expression = (
            "(SELECT a.severity FROM alerts AS a WHERE a.session_id = s.id "
            "ORDER BY a.id DESC LIMIT 1)"
        )
        event_conditions = ["e.occurred_at >= ?", "e.occurred_at < ?"]
        event_parameters: list[Any] = [start, end]
        if classification is not None:
            event_conditions.append(f"{classification_expression} = ?")
            event_parameters.append(classification)
        if severity is not None:
            event_conditions.append(f"COALESCE({severity_expression}, 'None') = ?")
            event_parameters.append(severity)
        event_parameters.append(500)
        events = _fetch_dataframe(
            connection,
            "SELECT e.occurred_at, s.source_ip, e.event_type, "
            f"{classification_expression} AS classification, "
            f"COALESCE({severity_expression}, 'None') AS severity, e.details "
            "FROM events AS e JOIN sessions AS s ON s.id = e.session_id "
            "WHERE "
            + " AND ".join(event_conditions)
            + " ORDER BY e.id DESC LIMIT ?",
            tuple(event_parameters),
        )
        if not events.empty:
            events["details"] = events["details"].map(
                lambda value: json.dumps(json.loads(value), ensure_ascii=False)
            )
        else:
            events = _empty_frame(EVENT_COLUMNS)

        alert_conditions = ["a.created_at >= ?", "a.created_at < ?"]
        alert_parameters: list[Any] = [start, end]
        if severity is not None:
            alert_conditions.append("a.severity = ?")
            alert_parameters.append(severity)
        alert_parameters.append(100)
        alerts = _fetch_dataframe(
            connection,
            "SELECT a.created_at, s.source_ip, a.severity, a.message "
            "FROM alerts AS a JOIN sessions AS s ON s.id = a.session_id "
            "WHERE "
            + " AND ".join(alert_conditions)
            + " ORDER BY a.id DESC LIMIT ?",
            tuple(alert_parameters),
        )
        if alerts.empty:
            alerts = _empty_frame(ALERT_COLUMNS)

        return {
            "summary": summary,
            "timeline": timeline[list(TIMELINE_COLUMNS)],
            "classifications": classifications[list(CLASSIFICATION_COLUMNS)],
            "sources": sources[list(SOURCE_COLUMNS)],
            "events": events[list(EVENT_COLUMNS)],
            "alerts": alerts[list(ALERT_COLUMNS)],
        }
    except sqlite3.Error:
        logger.exception("Dashboard read query failed for database '%s'.", db_path)
        raise
    finally:
        connection.close()
