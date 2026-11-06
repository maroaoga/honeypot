import pytest

from database.db import initialize_database, list_events, list_sessions
from honeypot.web_service import LOCALHOST, create_app


@pytest.fixture
def client_and_db(tmp_path):
    db_path = tmp_path / "web.db"
    initialize_database(db_path)
    app = create_app(db_path)
    app.config.update(TESTING=True)
    return app.test_client(), db_path


def test_get_login_logs_request(client_and_db):
    client, db_path = client_and_db

    response = client.get("/login")

    assert response.status_code == 200
    assert b'<form method="post" action="/login">' in response.data
    sessions = list_sessions(db_path=db_path)
    assert len(sessions) == 1
    events = list_events(session_id=sessions[0]["id"], db_path=db_path)
    assert events[0]["event_type"] == "http_request"
    assert events[0]["details"]["method"] == "GET"
    assert events[0]["details"]["path"] == "/login"


def test_post_logs_attempt_without_storing_password(client_and_db):
    client, db_path = client_and_db

    response = client.post(
        "/login",
        data={"username": "guest", "password": "do-not-store-this"},
    )

    assert response.status_code == 200
    assert b"Login failed." in response.data
    events = list_events(db_path=db_path)
    request_event = next(event for event in events if event["event_type"] == "http_request")
    attempt = next(event for event in events if event["event_type"] == "http_login_attempt")
    assert request_event["details"]["method"] == "POST"
    assert attempt["details"] == {
        "username": "guest",
        "username_truncated": False,
        "password_length": 17,
    }
    assert "do-not-store-this" not in str(attempt["details"])


def test_logs_unknown_requests_too(client_and_db):
    client, db_path = client_and_db

    response = client.get("/missing")

    assert response.status_code == 404
    events = list_events(db_path=db_path)
    assert len(events) == 1
    assert events[0]["event_type"] == "http_request"
    assert events[0]["details"]["path"] == "/missing"


def test_non_loopback_request_is_rejected(client_and_db):
    client, db_path = client_and_db

    response = client.get("/login", environ_overrides={"REMOTE_ADDR": "192.0.2.1"})

    assert response.status_code == 403
    assert list_sessions(db_path=db_path) == []


def test_loopback_alias_is_accepted_and_recorded(client_and_db):
    client, db_path = client_and_db

    response = client.get(
        "/login",
        environ_overrides={"REMOTE_ADDR": "127.0.0.2"},
    )

    assert response.status_code == 200
    assert list_sessions(db_path=db_path)[0]["source_ip"] == "127.0.0.2"


def test_app_uses_loopback_only_when_running(monkeypatch, tmp_path):
    from honeypot import web_service

    captured = {}

    def fake_run(app, **kwargs):
        captured.update(kwargs)

    monkeypatch.setattr(web_service.Flask, "run", fake_run)
    web_service.run_web_service(port=12345, db_path=tmp_path / "web.db")

    assert captured["host"] == LOCALHOST
    assert captured["debug"] is False
    assert captured["use_reloader"] is False


def test_web_entrypoint_uses_validated_yaml_and_env_database(tmp_path, monkeypatch):
    from honeypot import web_service

    settings_file = tmp_path / "settings.yaml"
    settings_file.write_text(
        "server:\n  host: '127.0.0.1'\n  tcp_port: 8023\n  web_port: 9091\n"
        "logging:\n  level: WARNING\n",
        encoding="utf-8",
    )
    captured = {}
    monkeypatch.setenv("HONEYPOT_DB_PATH", str(tmp_path / "custom.db"))
    monkeypatch.setattr(
        web_service,
        "run_web_service",
        lambda **kwargs: captured.update(kwargs),
    )

    web_service.main(["--config", str(settings_file)])

    assert captured == {
        "port": 9091,
        "db_path": str(tmp_path / "custom.db"),
    }
