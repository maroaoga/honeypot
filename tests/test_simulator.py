import csv
import json

import pytest
import yaml

from database.db import create_event, create_session, initialize_database, list_events
from simulator import runner
from simulator.runner import (
    DEFAULT_CONFIG_PATH,
    SimulationConfigError,
    load_simulation_config,
    run_simulation,
)


DEFAULT_VOLUMES = {
    "brute_force_sessions": 2,
    "port_scan_sessions": 2,
    "sql_injection_sessions": 2,
    "directory_probe_sessions": 2,
    "benign_sessions": 2,
    "brute_force_attempt_min": 5,
    "brute_force_attempt_max": 6,
}


def _write_config(
    tmp_path,
    *,
    seed=42,
    min_delay=0,
    max_delay=0,
    volumes=None,
    source_ips=None,
):
    data = {
        "seed": seed,
        "timing": {
            "min_delay_seconds": min_delay,
            "max_delay_seconds": max_delay,
            "low_and_slow_min_delay_seconds": 0,
            "low_and_slow_max_delay_seconds": 0,
            "low_and_slow_probability": 0,
        },
        "volumes": volumes or DEFAULT_VOLUMES,
        "source_ips": source_ips or ["127.0.0.1", "127.0.0.2", "127.0.0.3"],
    }
    config_file = tmp_path / "simulator.yaml"
    config_file.write_text(yaml.safe_dump(data), encoding="utf-8")
    return config_file


def _fake_network(db_path, monkeypatch):
    def new_session(event_type, details, source_ip):
        session_id = create_session(source_ip, db_path=db_path)
        create_event(session_id, event_type, details, db_path=db_path)
        return session_id

    def fake_tcp_login_attempts(
        credentials,
        *,
        port=runner.DEFAULT_TCP_PORT,
        source_ip="127.0.0.1",
        delay_between_attempts=None,
    ):
        session_id = new_session(
            "tcp_connection",
            {"service": "fake_login"},
            source_ip,
        )
        for username, password in credentials:
            create_event(
                session_id,
                "tcp_login_attempt",
                {"username": username, "password_length": len(password)},
                db_path=db_path,
            )
            if delay_between_attempts is not None:
                delay_between_attempts()

    def fake_probe_tcp(*, port=runner.DEFAULT_TCP_PORT, source_ip="127.0.0.1"):
        new_session("tcp_connection", {"service": "fake_login"}, source_ip)

    def fake_http_request(
        path,
        *,
        method="GET",
        form=None,
        port=runner.DEFAULT_WEB_PORT,
        source_ip="127.0.0.1",
    ):
        session_id = new_session(
            "http_request",
            {"method": method, "path": path, "content_type": "test"},
            source_ip,
        )
        if method == "POST":
            create_event(
                session_id,
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
        lambda limit, db_path=None: _list_sessions(db_path, limit),
    )
    monkeypatch.setattr(runner, "_tcp_login_attempts", fake_tcp_login_attempts)
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
    assert config.brute_force_sessions == 300
    assert config.brute_force_attempt_min == 5
    assert config.brute_force_attempt_max == 50
    assert len(config.source_ips) >= 3


@pytest.mark.parametrize(
    ("overrides", "message"),
    [
        ({"seed": True}, "seed"),
        ({"volumes": {"brute_force_sessions": 11}}, "volumes must contain exactly"),
        ({"source_ips": ["127.0.0.1", "127.0.0.2"]}, "at least three"),
        (
            {"source_ips": ["127.0.0.1", "127.0.0.2", "192.0.2.1"]},
            "loopback IPv4",
        ),
    ],
)
def test_rejects_malformed_simulator_config(tmp_path, overrides, message):
    data = {
        "seed": 42,
        "timing": {
            "min_delay_seconds": 0,
            "max_delay_seconds": 0,
            "low_and_slow_min_delay_seconds": 0,
            "low_and_slow_max_delay_seconds": 0,
            "low_and_slow_probability": 0,
        },
        "volumes": DEFAULT_VOLUMES,
        "source_ips": ["127.0.0.1", "127.0.0.2", "127.0.0.3"],
    }
    data.update(overrides)
    config_file = tmp_path / "invalid.yaml"
    config_file.write_text(yaml.safe_dump(data), encoding="utf-8")

    with pytest.raises(SimulationConfigError, match=message):
        load_simulation_config(config_file)


@pytest.mark.parametrize(
    ("volume_overrides", "timing", "message"),
    [
        ({"brute_force_sessions": 5001}, (0, 0), "brute_force_sessions"),
        ({"brute_force_attempt_min": 4}, (0, 0), "brute_force_attempt_min"),
        ({"brute_force_attempt_min": 8, "brute_force_attempt_max": 6}, (0, 0), "cannot exceed"),
        ({}, (3, 1), "min_delay_seconds"),
    ],
)
def test_rejects_out_of_range_volumes_and_timing(
    tmp_path,
    volume_overrides,
    timing,
    message,
):
    volumes = dict(DEFAULT_VOLUMES)
    volumes.update(volume_overrides)
    config_file = _write_config(
        tmp_path,
        volumes=volumes,
        min_delay=timing[0],
        max_delay=timing[1],
    )

    with pytest.raises(SimulationConfigError, match=message):
        load_simulation_config(config_file)


def test_simulation_labels_are_separate_and_use_three_local_sources(tmp_path, monkeypatch):
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
    assert {event["source_ip"] for event in _list_sessions(db_path, 100)} == {
        "127.0.0.1",
        "127.0.0.2",
        "127.0.0.3",
    }


def test_same_seed_repeats_generated_request_features(tmp_path, monkeypatch):
    config = load_simulation_config(_write_config(tmp_path))
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
            [(event["event_type"], event["details"]) for event in reversed(events)]
        )

    assert snapshots[0] == snapshots[1]


def test_simulation_surfaces_service_unavailable(tmp_path, monkeypatch):
    db_path = tmp_path / "honeypot.db"
    initialize_database(db_path)
    monkeypatch.setattr(runner, "list_sessions", lambda limit, db_path=None: [])
    monkeypatch.setattr(
        runner,
        "_tcp_login_attempts",
        lambda credentials, **kwargs: None,
    )
    config = load_simulation_config(
        _write_config(
            tmp_path,
            volumes={
                "brute_force_sessions": 1,
                "port_scan_sessions": 0,
                "sql_injection_sessions": 0,
                "directory_probe_sessions": 0,
                "benign_sessions": 0,
                "brute_force_attempt_min": 5,
                "brute_force_attempt_max": 5,
            },
        )
    )

    with pytest.raises(RuntimeError, match="No database sessions found"):
        run_simulation(
            config,
            labels_path=tmp_path / "labels.csv",
            db_path=db_path,
        )
