"""Generate small, labelled traffic samples against this project's local services."""

import argparse
import csv
import http.client
import logging
import random
import socket
import time
import urllib.parse
from dataclasses import dataclass
from pathlib import Path
from typing import Callable

import yaml

from database.db import DEFAULT_DB_PATH, list_sessions
from honeypot.tcp_service import DEFAULT_TCP_PORT, LOCALHOST
from honeypot.web_service import DEFAULT_WEB_PORT


DEFAULT_CONFIG_PATH = Path(__file__).resolve().parent.parent / "config" / "simulator.yaml"
DEFAULT_LABELS_PATH = Path(__file__).resolve().parent.parent / "data" / "ground_truth.csv"
NETWORK_TIMEOUT_SECONDS = 3
MAX_DELAY_SECONDS = 2.0
MAX_BRUTE_FORCE_ATTEMPTS = 10
MAX_PORT_SCAN_PROBES = 10
MAX_SQL_PROBES = 10
MAX_DIRECTORY_PROBES = 10
MAX_BENIGN_SESSIONS = 10
BRUTE_FORCE_CREDENTIALS = (
    ("guest", "not-a-real-password"),
    ("admin", "incorrect-example"),
    ("student", "example-only"),
    ("root", "invalid-credential"),
    ("user", "wrong-password"),
)
SQL_PROBES = (
    "'",
    '"',
    "' OR '1'='1",
    '" OR "1"="1',
    "admin' --",
)
DIRECTORY_PATHS = (
    "/admin",
    "/robots.txt",
    "/favicon.ico",
    "/static/",
    "/backup",
)
BENIGN_USERS = ("alice", "bob", "charlie", "dana", "erin")
BENIGN_PASSWORDS = ("sample-password", "not-a-secret", "example-value")


class SimulationConfigError(ValueError):
    """Raised when simulator configuration is invalid."""


@dataclass(frozen=True)
class SimulationConfig:
    seed: int
    min_delay_seconds: float
    max_delay_seconds: float
    brute_force_attempts: int
    port_scan_probes: int
    sql_injection_probes: int
    directory_probes: int
    benign_sessions: int


def _validate_mapping(value: object, name: str, expected_keys: set[str]) -> dict:
    if not isinstance(value, dict):
        raise SimulationConfigError(f"{name} must be a YAML mapping.")
    if set(value) != expected_keys:
        raise SimulationConfigError(
            f"{name} must contain exactly: {', '.join(sorted(expected_keys))}."
        )
    return value


def _validate_count(value: object, name: str, maximum: int) -> int:
    if type(value) is not int or not 0 <= value <= maximum:
        raise SimulationConfigError(f"{name} must be an integer from 0 through {maximum}.")
    return value


def _validate_delay(value: object, name: str) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise SimulationConfigError(f"{name} must be a number from 0 through {MAX_DELAY_SECONDS}.")
    if not 0 <= value <= MAX_DELAY_SECONDS:
        raise SimulationConfigError(f"{name} must be a number from 0 through {MAX_DELAY_SECONDS}.")
    return float(value)


def load_simulation_config(path: str | Path = DEFAULT_CONFIG_PATH) -> SimulationConfig:
    """Read and validate the simulator's YAML settings."""
    config_path = Path(path)
    try:
        contents = config_path.read_text(encoding="utf-8")
    except OSError as exc:
        raise SimulationConfigError(f"Unable to read simulator config '{config_path}': {exc}") from exc
    try:
        data = yaml.safe_load(contents)
    except yaml.YAMLError as exc:
        raise SimulationConfigError(f"Invalid simulator YAML: {exc}") from exc

    top = _validate_mapping(data, "simulator config", {"seed", "timing", "volumes"})
    seed = top["seed"]
    if type(seed) is not int or not 0 <= seed <= 4_294_967_295:
        raise SimulationConfigError("seed must be an integer from 0 through 4294967295.")

    timing = _validate_mapping(
        top["timing"],
        "timing",
        {"min_delay_seconds", "max_delay_seconds"},
    )
    min_delay = _validate_delay(timing["min_delay_seconds"], "min_delay_seconds")
    max_delay = _validate_delay(timing["max_delay_seconds"], "max_delay_seconds")
    if min_delay > max_delay:
        raise SimulationConfigError("min_delay_seconds cannot exceed max_delay_seconds.")

    volume_keys = {
        "brute_force_attempts",
        "port_scan_probes",
        "sql_injection_probes",
        "directory_probes",
        "benign_sessions",
    }
    volumes = _validate_mapping(top["volumes"], "volumes", volume_keys)
    return SimulationConfig(
        seed=seed,
        min_delay_seconds=min_delay,
        max_delay_seconds=max_delay,
        brute_force_attempts=_validate_count(
            volumes["brute_force_attempts"], "brute_force_attempts", MAX_BRUTE_FORCE_ATTEMPTS
        ),
        port_scan_probes=_validate_count(
            volumes["port_scan_probes"], "port_scan_probes", MAX_PORT_SCAN_PROBES
        ),
        sql_injection_probes=_validate_count(
            volumes["sql_injection_probes"], "sql_injection_probes", MAX_SQL_PROBES
        ),
        directory_probes=_validate_count(
            volumes["directory_probes"], "directory_probes", MAX_DIRECTORY_PROBES
        ),
        benign_sessions=_validate_count(
            volumes["benign_sessions"], "benign_sessions", MAX_BENIGN_SESSIONS
        ),
    )


def _receive_until(connection: socket.socket, marker: bytes) -> bytes:
    received = bytearray()
    while marker not in received:
        chunk = connection.recv(256)
        if not chunk:
            raise ConnectionError("TCP service closed before sending its prompt.")
        received.extend(chunk)
    return bytes(received)


def _tcp_login(
    username: str,
    password: str,
    *,
    port: int = DEFAULT_TCP_PORT,
) -> None:
    """Submit one dummy login to the fixed local TCP service."""
    with socket.create_connection(
        (LOCALHOST, port),
        timeout=NETWORK_TIMEOUT_SECONDS,
    ) as connection:
        connection.settimeout(NETWORK_TIMEOUT_SECONDS)
        _receive_until(connection, b"Username: ")
        connection.sendall(username.encode("utf-8") + b"\n")
        _receive_until(connection, b"Password: ")
        connection.sendall(password.encode("utf-8") + b"\n")
        _receive_until(connection, b"Login failed.")


def _probe_tcp_port(*, port: int = DEFAULT_TCP_PORT) -> None:
    """Check only the project's known fake TCP service, then disconnect."""
    with socket.create_connection(
        (LOCALHOST, port),
        timeout=NETWORK_TIMEOUT_SECONDS,
    ) as connection:
        connection.settimeout(NETWORK_TIMEOUT_SECONDS)
        _receive_until(connection, b"Username: ")


def _http_request(
    path: str,
    *,
    method: str = "GET",
    form: dict[str, str] | None = None,
    port: int = DEFAULT_WEB_PORT,
) -> int:
    """Send a single request to this project's fixed local fake web service."""
    if not path.startswith("/") or path.startswith("//"):
        raise ValueError("HTTP path must be a local absolute path.")
    body = None
    headers = {}
    if form is not None:
        body = urllib.parse.urlencode(form)
        headers["Content-Type"] = "application/x-www-form-urlencoded"
    connection = http.client.HTTPConnection(
        LOCALHOST,
        port,
        timeout=NETWORK_TIMEOUT_SECONDS,
    )
    try:
        connection.request(method, path, body=body, headers=headers)
        response = connection.getresponse()
        response.read()
        if response.status not in {200, 404}:
            raise RuntimeError(f"Local web service returned unexpected HTTP {response.status}.")
        return response.status
    finally:
        connection.close()


def _latest_session_id(db_path: str | Path = DEFAULT_DB_PATH) -> int:
    sessions = list_sessions(limit=1, db_path=db_path)
    if not sessions:
        raise RuntimeError("No database sessions found; did the local services log this request?")
    return int(sessions[0]["id"])


def run_simulation(
    config: SimulationConfig,
    *,
    labels_path: str | Path = DEFAULT_LABELS_PATH,
    db_path: str | Path = DEFAULT_DB_PATH,
    tcp_port: int = DEFAULT_TCP_PORT,
    web_port: int = DEFAULT_WEB_PORT,
) -> int:
    """Run configured sequential local traffic and save separate ground-truth labels.

    Stop other clients from using the honeypot while this runs so each newly
    logged session can be associated with the request that created it.
    """
    rng = random.Random(config.seed)
    for port_name, port in (("tcp_port", tcp_port), ("web_port", web_port)):
        if type(port) is not int or not 1 <= port <= 65535:
            raise ValueError(f"{port_name} must be an integer from 1 through 65535.")

    previous_session_id = (
        _latest_session_id(db_path) if list_sessions(limit=1, db_path=db_path) else 0
    )
    labels: list[tuple[int, str]] = []

    def run_labeled(label: str, operation: Callable[[], object]) -> None:
        nonlocal previous_session_id
        try:
            operation()
        except OSError as exc:
            raise RuntimeError(
                f"Could not reach the local honeypot while generating {label}: {exc}"
            ) from exc
        session_id = _latest_session_id(db_path)
        if session_id <= previous_session_id:
            raise RuntimeError(
                "The local service did not create a new session. "
                "Check that the right honeypot services are running."
            )
        previous_session_id = session_id
        labels.append((session_id, label))
        delay = rng.uniform(config.min_delay_seconds, config.max_delay_seconds)
        if delay:
            time.sleep(delay)

    credentials = rng.choices(
        BRUTE_FORCE_CREDENTIALS,
        k=config.brute_force_attempts,
    )
    for username, password in credentials:
        run_labeled(
            "brute_force",
            lambda u=username, p=password: _tcp_login(u, p, port=tcp_port),
        )

    port_probes: tuple[Callable[[], object], ...] = (
        lambda: _probe_tcp_port(port=tcp_port),
        lambda: _http_request("/", port=web_port),
    )
    selected_ports = rng.choices(port_probes, k=config.port_scan_probes)
    for probe in selected_ports:
        run_labeled("port_scan", probe)

    sql_probes = rng.choices(SQL_PROBES, k=config.sql_injection_probes)
    for probe in sql_probes:
        run_labeled(
            "sql_injection",
            lambda value=probe: _http_request(
                "/login",
                method="POST",
                form={"username": value, "password": "example-only"},
                port=web_port,
            ),
        )

    directory_paths = rng.choices(DIRECTORY_PATHS, k=config.directory_probes)
    for path in directory_paths:
        run_labeled(
            "directory_probe",
            lambda value=path: _http_request(value, port=web_port),
        )

    for _ in range(config.benign_sessions):
        username = rng.choice(BENIGN_USERS)
        password = rng.choice(BENIGN_PASSWORDS)
        run_labeled(
            "benign",
            lambda u=username, p=password: _http_request(
                "/login",
                method="POST",
                form={"username": u, "password": p},
                port=web_port,
            ),
        )

    output_path = Path(labels_path)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    try:
        with output_path.open("w", newline="", encoding="utf-8") as labels_file:
            writer = csv.writer(labels_file)
            writer.writerow(("session_id", "label"))
            writer.writerows(labels)
    except OSError:
        logger = logging.getLogger(__name__)
        logger.exception("Could not save simulation ground-truth labels to '%s'.", output_path)
        raise
    return len(labels)


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Generate bounded, labelled traffic against the local honeypot."
    )
    parser.add_argument(
        "--config",
        type=Path,
        default=DEFAULT_CONFIG_PATH,
        help=f"YAML simulation config (default: {DEFAULT_CONFIG_PATH})",
    )
    parser.add_argument(
        "--labels",
        type=Path,
        default=DEFAULT_LABELS_PATH,
        help=f"separate CSV ground-truth output (default: {DEFAULT_LABELS_PATH})",
    )
    args = parser.parse_args()
    config = load_simulation_config(args.config)
    count = run_simulation(config, labels_path=args.labels)
    print(f"Recorded {count} labelled sessions in {args.labels}")


if __name__ == "__main__":
    main()
