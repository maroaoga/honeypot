import asyncio

import pytest

from database.db import (
    initialize_database,
    list_events,
    list_sessions,
)
from honeypot.tcp_service import LOCALHOST, start_tcp_service


def test_tcp_service_binds_loopback_and_logs_connection_and_attempt(tmp_path):
    async def exercise_service():
        db_path = tmp_path / "tcp.db"
        initialize_database(db_path)
        server = await start_tcp_service(port=0, db_path=db_path)

        try:
            host, port = server.sockets[0].getsockname()[:2]
            assert host == LOCALHOST

            reader, writer = await asyncio.open_connection(LOCALHOST, port)
            assert await reader.readuntil(b"Username: ") == b"Username: "
            writer.write(b"guest\n")
            await writer.drain()
            assert await reader.readuntil(b"Password: ") == b"Password: "
            writer.write(b"do-not-store-this\n")
            await writer.drain()
            assert await reader.readline() == b"Login failed.\n"
            writer.close()
            await writer.wait_closed()
            await asyncio.sleep(0)
        finally:
            server.close()
            await server.wait_closed()

        sessions = list_sessions(db_path=db_path)
        assert len(sessions) == 1
        events = list_events(session_id=sessions[0]["id"], db_path=db_path)
        assert [event["event_type"] for event in reversed(events)] == [
            "tcp_connection",
            "tcp_login_attempt",
            "tcp_disconnect",
        ]
        attempt = next(
            event for event in events if event["event_type"] == "tcp_login_attempt"
        )
        assert attempt["details"] == {"username": "guest", "password_length": 17}
        assert "do-not-store-this" not in str(attempt["details"])

    asyncio.run(exercise_service())


def test_tcp_service_accepts_multiple_attempts_in_one_loopback_session(tmp_path):
    async def exercise_service():
        db_path = tmp_path / "tcp-multiple.db"
        initialize_database(db_path)
        server = await start_tcp_service(port=0, db_path=db_path)
        try:
            port = server.sockets[0].getsockname()[1]
            reader, writer = await asyncio.open_connection(
                LOCALHOST,
                port,
                local_addr=("127.0.0.2", 0),
            )
            for username in ("guest", "admin", "studnet"):
                assert await reader.readuntil(b"Username: ") == b"Username: "
                writer.write(username.encode() + b"\n")
                await writer.drain()
                assert await reader.readuntil(b"Password: ") == b"Password: "
                writer.write(b"dummy\n")
                await writer.drain()
                assert await reader.readline() == b"Login failed.\n"
            writer.close()
            await writer.wait_closed()
            await asyncio.sleep(0.02)
        finally:
            server.close()
            await server.wait_closed()

        sessions = list_sessions(db_path=db_path)
        assert len(sessions) == 1
        assert sessions[0]["source_ip"] == "127.0.0.2"
        events = list_events(session_id=sessions[0]["id"], db_path=db_path)
        assert sum(event["event_type"] == "tcp_login_attempt" for event in events) == 3

    asyncio.run(exercise_service())


def test_tcp_service_rejects_oversized_input_and_logs_protocol_error(tmp_path):
    async def exercise_service():
        db_path = tmp_path / "tcp-long.db"
        initialize_database(db_path)
        server = await start_tcp_service(port=0, db_path=db_path)
        try:
            port = server.sockets[0].getsockname()[1]
            reader, writer = await asyncio.open_connection(LOCALHOST, port)
            await reader.readuntil(b"Username: ")
            writer.write(b"x" * 513 + b"\n")
            await writer.drain()
            assert await reader.readline() == b"Invalid input.\n"
            writer.close()
            await writer.wait_closed()
            await asyncio.sleep(0.02)
        finally:
            server.close()
            await server.wait_closed()

        events = list_events(db_path=db_path)
        assert any(event["event_type"] == "tcp_protocol_error" for event in events)

    asyncio.run(exercise_service())


def test_tcp_service_rejects_invalid_port():
    with pytest.raises(ValueError, match="port"):
        asyncio.run(start_tcp_service(port=65536))


def test_tcp_entrypoint_uses_validated_yaml_and_env_database(tmp_path, monkeypatch):
    from honeypot import tcp_service

    settings_file = tmp_path / "settings.yaml"
    settings_file.write_text(
        "server:\n  host: '127.0.0.1'\n  tcp_port: 9090\n  web_port: 8082\n"
        "logging:\n  level: ERROR\n",
        encoding="utf-8",
    )
    captured = {}

    async def fake_run_tcp_service(**kwargs):
        captured.update(kwargs)

    monkeypatch.setenv("HONEYPOT_DB_PATH", str(tmp_path / "custom.db"))
    monkeypatch.setattr(tcp_service, "run_tcp_service", fake_run_tcp_service)

    tcp_service.main(["--config", str(settings_file)])

    assert captured == {
        "port": 9090,
        "db_path": str(tmp_path / "custom.db"),
    }
