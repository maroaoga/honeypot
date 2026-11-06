"""Run services, simulate local activity, classify it, adapt, and verify dashboard data."""

import argparse
import asyncio
import json
import logging
import os
import socket
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.request
from collections import Counter
from contextlib import contextmanager
from dataclasses import asdict, dataclass
from datetime import date, timedelta
from pathlib import Path
from typing import Any

from werkzeug.serving import make_server

from adaptive.rules import MALICIOUS_LABELS, observe_classification
from dashboard.data import load_dashboard_data
from database.db import (
    DEFAULT_DB_PATH,
    initialize_database,
    list_adaptive_actions,
    list_events,
    list_sessions,
)
from honeypot.tcp_service import LOCALHOST, start_tcp_service
from honeypot.web_service import create_app
from simulator.runner import (
    SimulationConfig,
    load_simulation_config,
    run_simulation,
)


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_INTEGRATION_CONFIG = ROOT / "config" / "integration.yaml"
DEFAULT_INTEGRATION_LABELS = ROOT / "data" / "integration_labels.csv"
DEFAULT_DASHBOARD_PORT = 8501
SERVICE_START_TIMEOUT_SECONDS = 10
DASHBOARD_START_TIMEOUT_SECONDS = 20
MAX_PIPELINE_SESSIONS = 1000
SQL_MARKERS = ("'", '"', "--", " OR ", " or ")
KNOWN_LOGIN_PATHS = {"/", "/login"}

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class PipelineResult:
    simulated_sessions: int
    classified_sessions: int
    classifications: dict[str, int]
    adaptive_actions: int
    alerts: int
    dashboard_sessions: int
    dashboard_events: int
    labels_path: str


class _TcpServiceThread:
    def __init__(self, db_path: str | Path):
        self.db_path = db_path
        self.ready = threading.Event()
        self.loop: asyncio.AbstractEventLoop | None = None
        self.server = None
        self.port: int | None = None
        self.error: BaseException | None = None
        self.thread = threading.Thread(target=self._serve, daemon=True)

    def _serve(self) -> None:
        self.loop = asyncio.new_event_loop()
        asyncio.set_event_loop(self.loop)

        async def serve() -> None:
            stopped = asyncio.Event()
            try:
                self.server = await start_tcp_service(port=0, db_path=self.db_path)
                self.port = self.server.sockets[0].getsockname()[1]
                self.stop_service = stopped.set
                self.ready.set()
                async with self.server:
                    await stopped.wait()
            except Exception as exc:
                self.error = exc
                self.ready.set()
                raise

        try:
            self.loop.run_until_complete(serve())
        except Exception as exc:
            if self.error is None:
                self.error = exc
        finally:
            pending = asyncio.all_tasks(self.loop)
            for task in pending:
                task.cancel()
            if pending:
                self.loop.run_until_complete(
                    asyncio.gather(*pending, return_exceptions=True)
                )
            self.loop.close()

    def start(self) -> int:
        self.thread.start()
        if not self.ready.wait(SERVICE_START_TIMEOUT_SECONDS):
            raise TimeoutError("Timed out while starting the local TCP service.")
        if self.error is not None:
            raise RuntimeError("Could not start the local TCP service.") from self.error
        if self.port is None:
            raise RuntimeError("TCP service started without a listening port.")
        return self.port

    def stop(self) -> None:
        stop_service = getattr(self, "stop_service", None)
        if stop_service is not None and self.loop is not None:
            self.loop.call_soon_threadsafe(stop_service)
        if self.thread.is_alive():
            self.thread.join(timeout=SERVICE_START_TIMEOUT_SECONDS)
        if self.thread.is_alive():
            raise TimeoutError("Local TCP service did not stop cleanly.")


class _WebServiceThread:
    def __init__(self, db_path: str | Path):
        self.server = make_server(
            LOCALHOST,
            0,
            create_app(db_path),
            threaded=True,
        )
        self.port = int(self.server.server_port)
        self.thread = threading.Thread(
            target=self.server.serve_forever,
            daemon=True,
        )

    def start(self) -> int:
        self.thread.start()
        return self.port

    def stop(self) -> None:
        self.server.shutdown()
        self.thread.join(timeout=SERVICE_START_TIMEOUT_SECONDS)
        self.server.server_close()
        if self.thread.is_alive():
            raise TimeoutError("Local web service did not stop cleanly.")


@contextmanager
def _service_ports(db_path: str | Path):
    tcp = _TcpServiceThread(db_path)
    web: _WebServiceThread | None = None
    tcp.start()
    try:
        web = _WebServiceThread(db_path)
        web.start()
        yield tcp.port, web.port
    finally:
        if web is not None:
            web.stop()
        tcp.stop()


def classify_session_events(events: list[dict[str, Any]]) -> tuple[str, float]:
    """Apply a transparent event-only classifier; never reads simulator labels."""
    event_types = {str(event["event_type"]) for event in events}
    details = [
        event["details"] if isinstance(event["details"], dict) else {}
        for event in events
    ]

    if "tcp_login_attempt" in event_types:
        return "brute_force", 0.95

    usernames = [
        str(item.get("username", ""))
        for item, event in zip(details, events)
        if event["event_type"] == "http_login_attempt"
    ]
    if any(any(marker in f" {username} " for marker in SQL_MARKERS) for username in usernames):
        return "sql_injection", 0.95

    paths = [
        str(item.get("path", ""))
        for item, event in zip(details, events)
        if event["event_type"] == "http_request"
    ]
    if any(path not in KNOWN_LOGIN_PATHS for path in paths):
        return "directory_probe", 0.9

    if "tcp_connection" in event_types or "/" in paths:
        return "port_scan", 0.9

    return "benign", 0.9


def _start_dashboard(db_path: str | Path, port: int) -> str:
    if type(port) is not int or not 1 <= port <= 65535:
        raise ValueError("dashboard_port must be an integer from 1 through 65535.")

    health_url = f"http://{LOCALHOST}:{port}/_stcore/health"
    try:
        with urllib.request.urlopen(health_url, timeout=1) as response:
            if response.status == 200 and response.read().decode("utf-8").strip() == "ok":
                return f"http://{LOCALHOST}:{port}"
    except (OSError, urllib.error.URLError):
        pass

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
        if probe.connect_ex((LOCALHOST, port)) == 0:
            raise RuntimeError(
                f"Port {port} is already in use by a service that is not "
                "a healthy Streamlit dashboard."
            )

    environment = os.environ.copy()
    environment["HONEYPOT_DB_PATH"] = str(Path(db_path).resolve())
    command = [
        sys.executable,
        "-m",
        "streamlit",
        "run",
        str(ROOT / "dashboard" / "app.py"),
        "--server.address",
        LOCALHOST,
        "--server.port",
        str(port),
        "--server.headless",
        "true",
    ]
    process = subprocess.Popen(
        command,
        cwd=ROOT,
        env=environment,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        creationflags=getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0)
        | getattr(subprocess, "DETACHED_PROCESS", 0),
    )
    deadline = time.monotonic() + DASHBOARD_START_TIMEOUT_SECONDS
    while time.monotonic() < deadline:
        if process.poll() is not None:
            raise RuntimeError(
                f"Streamlit exited during startup with status {process.returncode}."
            )
        try:
            with urllib.request.urlopen(health_url, timeout=1) as response:
                if response.status == 200 and response.read().decode("utf-8").strip() == "ok":
                    return f"http://{LOCALHOST}:{port}"
        except (OSError, urllib.error.URLError):
            time.sleep(0.25)
    process.terminate()
    raise TimeoutError(f"Streamlit did not become healthy on port {port}.")


def run_pipeline(
    *,
    config: SimulationConfig,
    db_path: str | Path = DEFAULT_DB_PATH,
    labels_path: str | Path = DEFAULT_INTEGRATION_LABELS,
    launch_dashboard: bool = False,
    dashboard_port: int = DEFAULT_DASHBOARD_PORT,
) -> PipelineResult:
    """Run a complete real localhost service → simulation → adaptation pipeline."""
    initialize_database(db_path)
    existing_sessions = list_sessions(limit=1, db_path=db_path)
    last_existing_id = int(existing_sessions[0]["id"]) if existing_sessions else 0

    simulated_count = 0
    with _service_ports(db_path) as (tcp_port, web_port):
        simulated_count = run_simulation(
            config,
            labels_path=labels_path,
            db_path=db_path,
            tcp_port=tcp_port,
            web_port=web_port,
        )

    generated_sessions = [
        session
        for session in reversed(
            list_sessions(limit=MAX_PIPELINE_SESSIONS, db_path=db_path)
        )
        if int(session["id"]) > last_existing_id
    ]
    if len(generated_sessions) != simulated_count:
        raise RuntimeError(
            "The number of newly logged sessions does not match the simulator output: "
            f"expected {simulated_count}, found {len(generated_sessions)}."
        )

    classification_counts: Counter[str] = Counter()
    for session in generated_sessions:
        session_id = int(session["id"])
        events = list_events(
            session_id=session_id,
            limit=100,
            db_path=db_path,
        )
        classification, confidence = classify_session_events(events)
        observe_classification(
            session_id,
            classification,
            confidence,
            db_path=db_path,
        )
        classification_counts[classification] += 1

    actions = list_adaptive_actions(limit=MAX_PIPELINE_SESSIONS, db_path=db_path)
    generated_ids = {int(session["id"]) for session in generated_sessions}
    run_actions = [
        action for action in actions if int(action["session_id"]) in generated_ids
    ]
    dashboard_data = load_dashboard_data(
        db_path,
        start_date=date.today() - timedelta(days=36500),
        end_date=date.today() + timedelta(days=1),
    )
    if dashboard_data["summary"]["sessions"] < simulated_count:
        raise RuntimeError("Dashboard query did not include the generated sessions.")
    if dashboard_data["summary"]["malicious_classifications"] < sum(
        count for label, count in classification_counts.items()
        if label in MALICIOUS_LABELS
    ):
        raise RuntimeError("Dashboard query did not include the new classifications.")

    if launch_dashboard:
        dashboard_url = _start_dashboard(db_path, dashboard_port)
        print(f"Dashboard is ready at {dashboard_url}")

    return PipelineResult(
        simulated_sessions=simulated_count,
        classified_sessions=sum(classification_counts.values()),
        classifications=dict(sorted(classification_counts.items())),
        adaptive_actions=len(run_actions),
        alerts=sum(
            1
            for action in run_actions
            if action["action_type"] == "classification_observed"
            and action["outcome"] == "alerted"
        ),
        dashboard_sessions=dashboard_data["summary"]["sessions"],
        dashboard_events=dashboard_data["summary"]["events"],
        labels_path=str(labels_path),
    )


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Run the complete local honeypot demonstration pipeline."
    )
    parser.add_argument("--config", type=Path, default=DEFAULT_INTEGRATION_CONFIG)
    parser.add_argument("--database", type=Path, default=DEFAULT_DB_PATH)
    parser.add_argument("--labels", type=Path, default=DEFAULT_INTEGRATION_LABELS)
    parser.add_argument(
        "--no-dashboard",
        action="store_true",
        help="populate and verify dashboard data without starting Streamlit",
    )
    parser.add_argument("--dashboard-port", type=int, default=DEFAULT_DASHBOARD_PORT)
    args = parser.parse_args()
    config = load_simulation_config(args.config)
    result = run_pipeline(
        config=config,
        db_path=args.database,
        labels_path=args.labels,
        launch_dashboard=not args.no_dashboard,
        dashboard_port=args.dashboard_port,
    )
    print(json.dumps(asdict(result), indent=2))


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    main()
