"""Streamlit entry point for the read-only honeypot operations dashboard."""

import os
import sqlite3
from datetime import date, timedelta

import pandas as pd
import streamlit as st

from dashboard.data import DashboardDatabaseError, load_dashboard_data
from database.db import DEFAULT_DB_PATH


SEVERITIES = ("low", "medium", "high", "critical")
DATABASE_ENV_VAR = "HONEYPOT_DB_PATH"


@st.cache_data(ttl=10, max_entries=16)
def _load_data(
    db_path: str,
    start_date: date,
    end_date: date,
    classification: str | None,
    severity: str | None,
) -> dict:
    return load_dashboard_data(
        db_path,
        start_date=start_date,
        end_date=end_date,
        classification=classification,
        severity=severity,
    )


def _database_path() -> str:
    return os.environ.get(DATABASE_ENV_VAR, str(DEFAULT_DB_PATH))


def _render_alerts(alerts: pd.DataFrame) -> None:
    with st.container(border=True):
        st.subheader("Recent alerts")
        if alerts.empty:
            st.caption("No alerts in this date range.")
            return
        st.dataframe(
            alerts,
            hide_index=True,
            column_config={
                "created_at": st.column_config.DatetimeColumn(
                    "Time",
                    format="MMM D, HH:mm:ss",
                ),
                "source_ip": st.column_config.TextColumn("Source IP"),
                "severity": st.column_config.TextColumn("Severity"),
                "message": st.column_config.TextColumn("Alert"),
            },
        )


def main() -> None:
    st.set_page_config(
        page_title="Honeypot observability",
        page_icon=":material/shield:",
        layout="wide",
        initial_sidebar_state="expanded",
    )
    with st.sidebar:
        st.title("Honeypot")
        st.caption("LOCAL SECURITY OBSERVABILITY")
        st.divider()
        st.subheader("Filters")
        today = date.today()
        date_range = st.date_input(
            "Date range",
            value=(today - timedelta(days=29), today),
            max_value=today,
            key="date_range",
        )
        if isinstance(date_range, tuple) and len(date_range) == 2:
            start_date, end_date = date_range
        else:
            start_date = end_date = date_range[0] if isinstance(date_range, tuple) else date_range

        if st.button("Refresh data", icon=":material/refresh:", width="stretch"):
            _load_data.clear()

    st.title("Honeypot observability")
    st.caption(
        "Local telemetry from the SQLite event store. Labels are sourced only "
        "from recorded database classifications."
    )

    try:
        overview = _load_data(
            _database_path(),
            start_date,
            end_date,
            None,
            None,
        )
    except DashboardDatabaseError as exc:
        with st.container(border=True):
            st.subheader("Database not ready")
            st.info(str(exc))
            st.code("python -m database.init_db", language="powershell")
        return
    except (OSError, ValueError, sqlite3.Error) as exc:
        st.error(f"Could not load dashboard data: {exc}")
        return

    classifications = overview["classifications"]["classification"].tolist()
    with st.sidebar:
        selected_classification = st.selectbox(
            "Classification",
            ["All classifications", *classifications],
            key="classification",
        )
        selected_severity = st.selectbox(
            "Severity",
            ["All severities", *SEVERITIES],
            key="severity",
        )
    classification_filter = (
        selected_classification
        if selected_classification != "All classifications"
        else None
    )
    severity_filter = (
        selected_severity if selected_severity != "All severities" else None
    )

    try:
        data = _load_data(
            _database_path(),
            start_date,
            end_date,
            classification_filter,
            severity_filter,
        )
    except (OSError, ValueError, sqlite3.Error) as exc:
        st.error(f"Could not load filtered dashboard data: {exc}")
        return

    summary = data["summary"]
    with st.container(horizontal=True):
        st.metric("Sessions", f"{summary['sessions']:,}", border=True)
        st.metric("Events", f"{summary['events']:,}", border=True)
        st.metric(
            "Malicious classifications",
            f"{summary['malicious_classifications']:,}",
            border=True,
        )
        st.metric("Alerts", f"{summary['alerts']:,}", border=True)
        st.metric("Unique sources", f"{summary['sources']:,}", border=True)

    if summary["sessions"] == 0 and summary["events"] == 0:
        with st.container(border=True):
            st.subheader("No activity yet")
            st.write(
                "There are no sessions or events in the selected date range. "
                "Start the localhost honeypot services and simulator, or choose "
                "a wider date range."
            )
            st.code(
                "python -m database.init_db\n"
                "python -m honeypot.tcp_service\n"
                "python -m honeypot.web_service",
                language="powershell",
            )
        _render_alerts(data["alerts"])
        return

    chart_column, class_column = st.columns(2)
    with chart_column:
        with st.container(border=True):
            st.subheader("Attack activity over time")
            st.caption(
                "Hourly recorded events and classifier-confirmed malicious sessions."
            )
            timeline = data["timeline"]
            if timeline.empty:
                st.caption("No activity to chart in this date range.")
            else:
                timeline = timeline.copy()
                timeline["hour"] = pd.to_datetime(timeline["hour"])
                st.line_chart(
                    timeline,
                    x="hour",
                    y=["observed_events", "malicious_classifications"],
                    x_label="Time",
                    y_label="Count",
                )
    with class_column:
        with st.container(border=True):
            st.subheader("Classification breakdown")
            st.caption("Observed classifier results saved in the database.")
            classification_data = data["classifications"]
            if classification_data.empty:
                st.info(
                    "No classifications have been recorded yet. "
                    "The chart will populate when adaptive decisions are stored."
                )
            else:
                st.bar_chart(
                    classification_data,
                    x="classification",
                    y="count",
                    x_label="Classification",
                    y_label="Sessions",
                )

    source_column, alert_column = st.columns([1, 1.4])
    with source_column:
        with st.container(border=True):
            st.subheader("Top source IPs")
            sources = data["sources"]
            if sources.empty:
                st.caption("No source activity in this date range.")
            else:
                st.dataframe(
                    sources,
                    hide_index=True,
                    column_config={
                        "source_ip": st.column_config.TextColumn("Source IP"),
                        "session_count": st.column_config.NumberColumn(
                            "Sessions",
                            format="%d",
                        ),
                        "event_count": st.column_config.NumberColumn(
                            "Events",
                            format="%d",
                        ),
                    },
                )
    with alert_column:
        _render_alerts(data["alerts"])

    with st.container(border=True):
        st.subheader("Event explorer")
        st.caption(
            "Filtered records from the events table. Classification and severity "
            "are joined from database records."
        )
        events = data["events"].copy()
        if events.empty:
            st.info("No events match the selected date, classification, and severity.")
        else:
            events["occurred_at"] = pd.to_datetime(events["occurred_at"])
            st.dataframe(
                events,
                hide_index=True,
                column_config={
                    "occurred_at": st.column_config.DatetimeColumn(
                        "Time",
                        format="MMM D, HH:mm:ss",
                    ),
                    "source_ip": st.column_config.TextColumn("Source IP"),
                    "event_type": st.column_config.TextColumn("Event"),
                    "classification": st.column_config.TextColumn("Classification"),
                    "severity": st.column_config.TextColumn("Severity"),
                    "details": st.column_config.TextColumn("Details", width="large"),
                },
            )


if __name__ == "__main__":
    main()
