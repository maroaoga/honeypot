import csv
import json

import pytest

from database.db import create_event, create_session, initialize_database, list_events
from simulator import runner
from simulator.runner import (
    DEFAULT_CONFIG_PATH,
    SimulationConfigError,
    load_simulation_config,
    run_simulation,
)


def _write_config(tmp_path, *, seed=42, min_delay=0, max_delay=0, volumes=None):
    if volumes is None:
        volumes = {
            "brute_force_attempts": 2,
            "port_scan_probes": 2,
            "sql_injection_probes": 2,
            "directory_probes": 2,
            "benign_sessions": 2,
        }
    config_file = tmp_path / "simulator.yaml"
    config_file.write_text(
        f"seed: {seed}\n"
        f"timing:\n  min_delay_seconds: {min_delay}\n"
        f"  max_delay_seconds: {max_delay}\n"
        "volumes:\n"
        + "".join(f"  {key}: {value}\n" for key, value in volumes.items()),
        encoding="utf-8",
    )
    return config_file


def _fake_network(db_path, monkeypatch):
    test_db_path = db_path

    def new_session(event_type, details):
        session_id = create_session("127.0.0.1", db_path=db_path)
        create_event(session_id, event_type, details, db_path=db_path)

    def fake_tcp_login(username, password, *, port=runner.DEFAULT_TCP_PORT):
        new_session(
            "tcp_login_attempt",
            {"username": username, "password_length": len(password)},
        )

    def fake_probe_tcp(*, port=runner.DEFAULT_TCP_PORT):
        new_session("tcp_connection", {"service": "fake_login"})

    def fake_http_request(path, *, method="GET", form=None, port=runner.DEFAULT_WEB_PORT):
        new_session(
            "http_request",
            {"method": method, "path": path, "content_type": "test"},
        )
        if method == "POST":
            new_session_id = runner._latest_session_id(db_path)
            create_event(
                new_session_id,
                "http_login_attempt",
                {
                    "username": form["username"],
                    "password_length": len(form["password"]),
                },
                db_path=db_path,
            )
        return 200

    monkeypatch.setattr(
        runner,
        "list_sessions",
        lambda limit, db_path=None: _list_sessions(test_db_path, limit),
    )
    monkeypatch.setattr(runner, "_tcp_login", fake_tcp_login)
    monkeypatch.setattr(runner, "_probe_tcp_port", fake_probe_tcp)
    monkeypatch.setattr(runner, "_http_request", fake_http_request)


def _list_sessions(db_path, limit):
    from database.db import list_sessions

    return list_sessions(limit=limit, db_path=db_path)


def test_default_config_is_present_and_loopback_targets_are_fixed():
    config = load_simulation_config(DEFAULT_CONFIG_PATH)

    assert config.seed == 20261106
    assert runner.LOCALHOST == "127.0.0.1"
    assert runner.DEFAULT_TCP_PORT == 8022
    assert runner.DEFAULT_WEB_PORT == 8081


@pytest.mark.parametrize(
    ("overrides", "message"),
    [
        ({"seed": True}, "seed"),
        ({"volumes": {"brute_force_attempts": 11}}, "volumes must contain exactly"),
    ],
)
def test_rejects_malformed_simulator_config(tmp_path, overrides, message):
    config_file = tmp_path / "invalid.yaml"
    data = {
        "seed": 42,
        "timing": {"min_delay_seconds": 0, "max_delay_seconds": 0},
        "volumes": {
            "brute_force_attempts": 1,
            "port_scan_probes": 1,
            "sql_injection_probes": 1,
            "directory_probes": 1,
            "benign_sessions": 1,
        },
    }
    data.update(overrides)
    import yaml

    config_file.write_text(yaml.safe_dump(data), encoding="utf-8")

    with pytest.raises(SimulationConfigError, match=message):
        load_simulation_config(config_file)


@pytest.mark.parametrize(
    ("volumes", "timing", "message"),
    [
        (
            {
                "brute_force_attempts": 11,
                "port_scan_probes": 1,
                "sql_injection_probes": 1,
                "directory_probes": 1,
                "benign_sessions": 1,
            },
            (0, 0),
            "brute_force_attempts",
        ),
        (
            {
                "brute_force_attempts": 1,
                "port_scan_probes": 11,
                "sql_injection_probes": 1,
                "directory_probes": 1,
                "benign_sessions": 1,
            },
            (0, 0),
            "port_scan_probes",
        ),
        (
            {
                "brute_force_attempts": 1,
                "port_scan_probes": 1,
                "sql_injection_probes": 1,
                "directory_probes": 1,
                "benign_sessions": 1,
            },
            (3, 1),
            "min_delay_seconds",
        ),
    ],
)
def test_rejects_out_of_range_volumes_and_timing(tmp_path, volumes, timing, message):
    config_file = _write_config(
        tmp_path,
        volumes=volumes,
        min_delay=timing[0],
        max_delay=timing[1],
    )

    with pytest.raises(SimulationConfigError, match=message):
        load_simulation_config(config_file)


def test_simulation_labels_are_separate_from_database_features(tmp_path, monkeypatch):
    db_path = tmp_path / "honeypot.db"
    initialize_database(db_path)
    _fake_network(db_path, monkeypatch)
    config = load_simulation_config(_write_config(tmp_path))
    labels_path = tmp_path / "labels.csv"

    count = run_simulation(config, labels_path=labels_path, db_path=db_path)

    with labels_path.open(newline="", encoding="utf-8") as labels_file:
        labels = list(csv.DictReader(labels_file))
    events = list_events(db_path=db_path)
    assert count == 10
    assert {row["label"] for row in labels} == {
        "brute_force",
        "port_scan",
        "sql_injection",
        "directory_probe",
        "benign",
    }
    assert all("label" not in event["details"] for event in events)
    assert all(
        label not in json.dumps(event["details"])
        for event in events
        for label in {row["label"] for row in labels}
    )
    assert {int(row["session_id"]) for row in labels} <= {
        event["session_id"] for event in events
    }


def test_same_seed_repeats_generated_request_features(tmp_path, monkeypatch):
    config_path = _write_config(tmp_path)
    config = load_simulation_config(config_path)
    snapshots = []

    for run_number in range(2):
        db_path = tmp_path / f"run-{run_number}.db"
        initialize_database(db_path)
        _fake_network(db_path, monkeypatch)
        run_simulation(
            config,
            labels_path=tmp_path / f"labels-{run_number}.csv",
            db_path=db_path,
        )
        events = list_events(db_path=db_path)
        snapshots.append(
            [
                (event["event_type"], event["details"])
                for event in reversed(events)
            ]
        )

    assert snapshots[0] == snapshots[1]


def test_simulation_surfaces_service_unavailable(tmp_path, monkeypatch):
    db_path = tmp_path / "honeypot.db"
    initialize_database(db_path)
    monkeypatch.setattr(runner, "list_sessions", lambda limit, db_path=None: [])
    monkeypatch.setattr(
        runner,
        "_tcp_login",
        lambda username, password, *, port=runner.DEFAULT_TCP_PORT: None,
    )
    config = load_simulation_config(
        _write_config(
            tmp_path,
            volumes={
                "brute_force_attempts": 1,
                "port_scan_probes": 0,
                "sql_injection_probes": 0,
                "directory_probes": 0,
                "benign_sessions": 0,
            },
        )
    )

    with pytest.raises(RuntimeError, match="No database sessions found"):
        run_simulation(
            config,
            labels_path=tmp_path / "labels.csv",
            db_path=db_path,
        )
