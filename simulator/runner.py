"""Generate labelled traffic against this project's loopback-only local services."""

import argparse
import csv
import http.client
import ipaddress
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
MAX_SESSIONS_PER_CLASS = 1000
MIN_BRUTE_FORCE_ATTEMPTS = 5
MAX_BRUTE_FORCE_ATTEMPTS = 50
DEFAULT_SOURCE_IPS = ("127.0.0.1", "127.0.0.2", "127.0.0.3")
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
BENIGN_USERS = ("alice", "bob", "charlie", "dana", "erin", "alcie", "studnet")
BENIGN_PASSWORDS = (
    "sample-password",
    "not-a-secret",
    "example-value",
    "sample-" + "x" * 128,
    "sample-" + "y" * 1024,
    "sample-" + "z" * 4096,
)


class SimulationConfigError(ValueError):
    """Raised when simulator configuration is invalid."""


@dataclass(frozen=True)
class SimulationConfig:
    seed: int
    min_delay_seconds: float
    max_delay_seconds: float
    brute_force_sessions: int
    port_scan_sessions: int
    sql_injection_sessions: int
    directory_probe_sessions: int
    benign_sessions: int
    brute_force_attempt_min: int = MIN_BRUTE_FORCE_ATTEMPTS
    brute_force_attempt_max: int = MAX_BRUTE_FORCE_ATTEMPTS
    low_and_slow_min_delay_seconds: float = 0.01
    low_and_slow_max_delay_seconds: float = 0.03
    low_and_slow_probability: float = 0.2
    source_ips: tuple[str, ...] = DEFAULT_SOURCE_IPS


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


def _validate_source_ip(source_ip: str) -> str:
    if not isinstance(source_ip, str):
        raise ValueError("source_ip must be a loopback IPv4 address.")
    try:
        address = ipaddress.ip_address(source_ip)
    except ValueError as exc:
        raise ValueError("source_ip must be a loopback IPv4 address.") from exc
    if not isinstance(address, ipaddress.IPv4Address) or not address.is_loopback:
        raise ValueError("source_ip must be a loopback IPv4 address.")
    return str(address)


def _validate_probability(value: object, name: str) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise SimulationConfigError(f"{name} must be a number from 0 through 1.")
    if not 0 <= value <= 1:
        raise SimulationConfigError(f"{name} must be a number from 0 through 1.")
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

    top = _validate_mapping(
        data,
        "simulator config",
        {"seed", "timing", "volumes", "source_ips"},
    )
    seed = top["seed"]
    if type(seed) is not int or not 0 <= seed <= 4_294_967_295:
        raise SimulationConfigError("seed must be an integer from 0 through 4294967295.")

    timing = _validate_mapping(
        top["timing"],
        "timing",
        {
            "min_delay_seconds",
            "max_delay_seconds",
            "low_and_slow_min_delay_seconds",
            "low_and_slow_max_delay_seconds",
            "low_and_slow_probability",
        },
    )
    min_delay = _validate_delay(timing["min_delay_seconds"], "min_delay_seconds")
    max_delay = _validate_delay(timing["max_delay_seconds"], "max_delay_seconds")
    if min_delay > max_delay:
        raise SimulationConfigError("min_delay_seconds cannot exceed max_delay_seconds.")
    slow_min_delay = _validate_delay(
        timing["low_and_slow_min_delay_seconds"],
        "low_and_slow_min_delay_seconds",
    )
    slow_max_delay = _validate_delay(
        timing["low_and_slow_max_delay_seconds"],
        "low_and_slow_max_delay_seconds",
    )
    if slow_min_delay > slow_max_delay:
        raise SimulationConfigError(
            "low_and_slow_min_delay_seconds cannot exceed "
            "low_and_slow_max_delay_seconds."
        )
    slow_probability = _validate_probability(
        timing["low_and_slow_probability"],
        "low_and_slow_probability",
    )

    volume_keys = {
        "brute_force_sessions",
        "port_scan_sessions",
        "sql_injection_sessions",
        "directory_probe_sessions",
        "benign_sessions",
        "brute_force_attempt_min",
        "brute_force_attempt_max",
    }
    volumes = _validate_mapping(top["volumes"], "volumes", volume_keys)
    attempt_min = volumes["brute_force_attempt_min"]
    attempt_max = volumes["brute_force_attempt_max"]
    if type(attempt_min) is not int or not MIN_BRUTE_FORCE_ATTEMPTS <= attempt_min <= MAX_BRUTE_FORCE_ATTEMPTS:
        raise SimulationConfigError("brute_force_attempt_min must be from 5 through 50.")
    if type(attempt_max) is not int or not MIN_BRUTE_FORCE_ATTEMPTS <= attempt_max <= MAX_BRUTE_FORCE_ATTEMPTS:
        raise SimulationConfigError("brute_force_attempt_max must be from 5 through 50.")
    if attempt_min > attempt_max:
        raise SimulationConfigError("brute_force_attempt_min cannot exceed brute_force_attempt_max.")

    source_ips_value = top["source_ips"]
    if (
        not isinstance(source_ips_value, list)
        or len(source_ips_value) < 3
        or any(not isinstance(value, str) for value in source_ips_value)
        or len(set(source_ips_value)) != len(source_ips_value)
    ):
        raise SimulationConfigError("source_ips must contain at least three unique loopback IPv4 addresses.")
    source_ips: list[str] = []
    for value in source_ips_value:
        try:
            address = ipaddress.ip_address(value)
        except ValueError as exc:
            raise SimulationConfigError("source_ips must contain loopback IPv4 addresses.") from exc
        if not isinstance(address, ipaddress.IPv4Address) or not address.is_loopback:
            raise SimulationConfigError("source_ips must contain loopback IPv4 addresses.")
        source_ips.append(str(address))

    return SimulationConfig(
        seed=seed,
        min_delay_seconds=min_delay,
        max_delay_seconds=max_delay,
        brute_force_sessions=_validate_count(
            volumes["brute_force_sessions"], "brute_force_sessions", MAX_SESSIONS_PER_CLASS
        ),
        port_scan_sessions=_validate_count(
            volumes["port_scan_sessions"], "port_scan_sessions", MAX_SESSIONS_PER_CLASS
        ),
        sql_injection_sessions=_validate_count(
            volumes["sql_injection_sessions"], "sql_injection_sessions", MAX_SESSIONS_PER_CLASS
        ),
        directory_probe_sessions=_validate_count(
            volumes["directory_probe_sessions"], "directory_probe_sessions", MAX_SESSIONS_PER_CLASS
        ),
        benign_sessions=_validate_count(
            volumes["benign_sessions"], "benign_sessions", MAX_SESSIONS_PER_CLASS
        ),
        brute_force_attempt_min=attempt_min,
        brute_force_attempt_max=attempt_max,
        low_and_slow_min_delay_seconds=slow_min_delay,
        low_and_slow_max_delay_seconds=slow_max_delay,
        low_and_slow_probability=slow_probability,
        source_ips=tuple(source_ips),
    )


def _receive_until(
    connection: socket.socket,
    marker: bytes,
    *,
    buffer: bytearray | None = None,
) -> bytes:
    received = buffer if buffer is not None else bytearray()
    while True:
        marker_index = received.find(marker)
        if marker_index >= 0:
            marker_end = marker_index + len(marker)
            result = bytes(received[:marker_end])
            del received[:marker_end]
            return result
        chunk = connection.recv(256)
        if not chunk:
            raise ConnectionError("TCP service closed before sending its prompt.")
        received.extend(chunk)


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


def _tcp_login_attempts(
        credentials: list[tuple[str, str]],
        *,
        port: int = DEFAULT_TCP_PORT,
        source_ip: str = "127.0.0.1",
        delay_between_attempts: Callable[[], float] | None = None,
) -> None:
        """Submit multiple dummy attempts over one local TCP session."""
        if not credentials or len(credentials) > MAX_BRUTE_FORCE_ATTEMPTS:
            raise ValueError("credentials must contain from 1 through 50 attempts.")
        source_ip = _validate_source_ip(source_ip)
        connection = socket.create_connection(
            (LOCALHOST, port),
            timeout=NETWORK_TIMEOUT_SECONDS,
            source_address=(source_ip, 0),
        )
        with connection:
            connection.settimeout(NETWORK_TIMEOUT_SECONDS)
            response_buffer = bytearray()
            for index, (username, password) in enumerate(credentials):
                _receive_until(connection, b"Username: ", buffer=response_buffer)
                connection.sendall(username.encode("utf-8") + b"\n")
                _receive_until(connection, b"Password: ", buffer=response_buffer)
                connection.sendall(password.encode("utf-8") + b"\n")
                _receive_until(connection, b"Login failed.", buffer=response_buffer)
                if index + 1 < len(credentials) and delay_between_attempts is not None:
                    time.sleep(delay_between_attempts())


def _probe_tcp_port(
    *,
    port: int = DEFAULT_TCP_PORT,
    source_ip: str = "127.0.0.1",
) -> None:
    """Check only the project's known fake TCP service, then disconnect."""
    source_ip = _validate_source_ip(source_ip)
    with socket.create_connection(
        (LOCALHOST, port),
        timeout=NETWORK_TIMEOUT_SECONDS,
        source_address=(source_ip, 0),
    ) as connection:
        connection.settimeout(NETWORK_TIMEOUT_SECONDS)
        _receive_until(connection, b"Username: ")


def _http_request(
    path: str,
    *,
    method: str = "GET",
    form: dict[str, str] | None = None,
    port: int = DEFAULT_WEB_PORT,
    source_ip: str = "127.0.0.1",
) -> int:
    """Send a single request to this project's fixed local fake web service."""
    if not path.startswith("/") or path.startswith("//"):
        raise ValueError("HTTP path must be a local absolute path.")
    body = None
    headers = {}
    if form is not None:
        body = urllib.parse.urlencode(form)
        headers["Content-Type"] = "application/x-www-form-urlencoded"
    source_ip = _validate_source_ip(source_ip)

    class LocalHTTPConnection(http.client.HTTPConnection):
        def connect(self) -> None:
            self.sock = socket.create_connection(
                (self.host, self.port),
                timeout=self.timeout,
                source_address=(source_ip, 0),
            )

    connection = LocalHTTPConnection(LOCALHOST, port, timeout=NETWORK_TIMEOUT_SECONDS)
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

    if len(config.source_ips) < 3 or any(
        not ipaddress.ip_address(address).is_loopback for address in config.source_ips
    ):
        raise ValueError("source_ips must contain at least three loopback addresses.")

    operations: list[tuple[str, Callable[[str], object], bool]] = []
    for _ in range(config.brute_force_sessions):
        attempt_count = rng.randint(
            config.brute_force_attempt_min,
            config.brute_force_attempt_max,
        )
        credentials = [
            rng.choice(BRUTE_FORCE_CREDENTIALS)
            for _ in range(attempt_count)
        ]
        is_slow = rng.random() < config.low_and_slow_probability
        operations.append(
            (
                "brute_force",
                lambda source, values=credentials, slow=is_slow: _tcp_login_attempts(
                    values,
                    port=tcp_port,
                    source_ip=source,
                    delay_between_attempts=(
                        (lambda: rng.uniform(
                            config.low_and_slow_min_delay_seconds,
                            config.low_and_slow_max_delay_seconds,
                        ))
                        if slow
                        else None
                    ),
                ),
                is_slow,
            )
        )

    for _ in range(config.port_scan_sessions):
        if rng.choice((True, False)):
            operations.append(
                (
                    "port_scan",
                    lambda source: _probe_tcp_port(
                        port=tcp_port,
                        source_ip=source,
                    ),
                    rng.random() < config.low_and_slow_probability,
                )
            )
        else:
            operations.append(
                (
                    "port_scan",
                    lambda source: _http_request(
                        "/",
                        port=web_port,
                        source_ip=source,
                    ),
                    rng.random() < config.low_and_slow_probability,
                )
            )

    for _ in range(config.sql_injection_sessions):
        probe = rng.choice(SQL_PROBES)
        operations.append(
            (
                "sql_injection",
                lambda source, value=probe: _http_request(
                    "/login",
                    method="POST",
                    form={"username": value, "password": "example-only"},
                    port=web_port,
                    source_ip=source,
                ),
                rng.random() < config.low_and_slow_probability,
            )
        )

    for _ in range(config.directory_probe_sessions):
        path_value = rng.choice(DIRECTORY_PATHS)
        operations.append(
            (
                "directory_probe",
                lambda source, value=path_value: _http_request(
                    value,
                    port=web_port,
                    source_ip=source,
                ),
                rng.random() < config.low_and_slow_probability,
            )
        )

    for _ in range(config.benign_sessions):
        username = rng.choice(BENIGN_USERS)
        password = rng.choice(BENIGN_PASSWORDS)
        operations.append(
            (
                "benign",
                lambda source, u=username, p=password: _http_request(
                    "/login",
                    method="POST",
                    form={"username": u, "password": p},
                    port=web_port,
                    source_ip=source,
                ),
                False,
            )
        )

    rng.shuffle(operations)
    for label, operation, is_slow in operations:
        source_ip = rng.choice(config.source_ips)
        run_labeled(
            label,
            lambda op=operation, source=source_ip: op(source),
        )
        if is_slow and config.low_and_slow_max_delay_seconds:
            time.sleep(
                rng.uniform(
                    config.low_and_slow_min_delay_seconds,
                    config.low_and_slow_max_delay_seconds,
                )
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
    from config.environment import database_path

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
    parser.add_argument(
        "--database",
        type=Path,
        default=database_path() or DEFAULT_DB_PATH,
    )
    args = parser.parse_args()
    config = load_simulation_config(args.config)
    count = run_simulation(
        config,
        labels_path=args.labels,
        db_path=args.database,
    )
    print(f"Recorded {count} labelled sessions in {args.labels}")


if __name__ == "__main__":
    main()
