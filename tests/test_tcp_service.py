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
        ]
        attempt = next(
            event for event in events if event["event_type"] == "tcp_login_attempt"
        )
        assert attempt["details"] == {"username": "guest", "password_length": 17}
        assert "do-not-store-this" not in str(attempt["details"])

    asyncio.run(exercise_service())


def test_tcp_service_rejects_invalid_port():
    with pytest.raises(ValueError, match="port"):
        asyncio.run(start_tcp_service(port=65536))
