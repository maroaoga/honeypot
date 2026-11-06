"""A line-based, fake login service that listens only on localhost."""

import asyncio
import argparse
import ipaddress
import logging
import sqlite3
from functools import partial
from pathlib import Path
from typing import Final

from adaptive.rules import SCAN_BANNER, get_source_controls
from database.db import DEFAULT_DB_PATH, create_event, create_session


logger = logging.getLogger(__name__)
LOCALHOST: Final = "127.0.0.1"
DEFAULT_TCP_PORT: Final = 8022
MAX_LINE_BYTES: Final = 512
CLIENT_TIMEOUT_SECONDS: Final = 15
MAX_ATTEMPTS_PER_CONNECTION: Final = 50


def _client_ip(writer: asyncio.StreamWriter) -> str:
    peer = writer.get_extra_info("peername")
    candidate = peer[0] if isinstance(peer, tuple) and peer else ""
    try:
        return str(ipaddress.ip_address(candidate))
    except ValueError:
        return LOCALHOST


async def handle_client(
    reader: asyncio.StreamReader,
    writer: asyncio.StreamWriter,
    *,
    db_path: str | Path = DEFAULT_DB_PATH,
) -> None:
    """Log one connection and up to 50 fake username/password attempts."""
    session_id: int | None = None
    source_ip = _client_ip(writer)
    controls = None
    try:
        session_id = create_session(source_ip, db_path=db_path)
        create_event(
            session_id,
            "tcp_connection",
            {"service": "fake_login"},
            db_path=db_path,
        )
        controls = get_source_controls(source_ip, db_path=db_path)
    except sqlite3.Error:
        logger.exception("Could not record incoming TCP connection.")
        writer.write(b"Service unavailable.\n")
        try:
            await writer.drain()
        except ConnectionError:
            logger.debug("TCP client disconnected before the error response.")
        return

    try:
        if controls is not None and controls.rate_limited:
            writer.write(b"Rate limited. Try again later.\n")
            await writer.drain()
            return
        if controls is not None and controls.scan_banner:
            writer.write(f"{SCAN_BANNER}\n".encode("utf-8"))
        for attempt_number in range(MAX_ATTEMPTS_PER_CONNECTION):
            writer.write(b"Username: ")
            await writer.drain()
            username = await _read_line(reader)
            if username is None:
                create_event(session_id, "tcp_disconnect", db_path=db_path)
                return

            writer.write(b"Password: ")
            await writer.drain()
            password = await _read_line(reader)
            if password is None:
                create_event(session_id, "tcp_disconnect", db_path=db_path)
                return

            create_event(
                session_id,
                "tcp_login_attempt",
                {
                    "username": username,
                    "password_length": len(password),
                },
                db_path=db_path,
            )
            writer.write(b"Login failed.\n")
            await writer.drain()
            if attempt_number + 1 == MAX_ATTEMPTS_PER_CONNECTION:
                return
    except (asyncio.TimeoutError, UnicodeDecodeError, ValueError) as exc:
        try:
            create_event(
                session_id,
                "tcp_protocol_error",
                {"error": type(exc).__name__},
                db_path=db_path,
            )
        except sqlite3.Error:
            logger.exception("Could not record TCP protocol error.")
        writer.write(b"Invalid input.\n")
        try:
            await writer.drain()
        except ConnectionError:
            logger.debug("TCP client disconnected before the error response.")
    except sqlite3.Error:
        logger.exception("Could not record TCP login attempt.")
        writer.write(b"Service unavailable.\n")
        try:
            await writer.drain()
        except ConnectionError:
            logger.debug("TCP client disconnected before the error response.")
    except ConnectionError:
        logger.info("TCP client disconnected during login.")
    finally:
        writer.close()
        try:
            await writer.wait_closed()
        except ConnectionError:
            logger.debug("TCP connection closed with a transport error.")


async def _read_line(reader: asyncio.StreamReader) -> str | None:
    raw_line = await asyncio.wait_for(
        reader.readline(),
        timeout=CLIENT_TIMEOUT_SECONDS,
    )
    if not raw_line:
        return None
    if len(raw_line) > MAX_LINE_BYTES:
        raise ValueError("Input line is too long.")
    return raw_line.rstrip(b"\r\n").decode("utf-8")


async def start_tcp_service(
    *,
    port: int = DEFAULT_TCP_PORT,
    db_path: str | Path = DEFAULT_DB_PATH,
) -> asyncio.AbstractServer:
    """Start the fake login service on 127.0.0.1 and return its server."""
    if type(port) is not int or not 0 <= port <= 65535:
        raise ValueError("port must be an integer from 0 through 65535.")
    handler = partial(handle_client, db_path=db_path)
    server = await asyncio.start_server(
        handler,
        host=LOCALHOST,
        port=port,
        limit=MAX_LINE_BYTES + 1,
    )
    bound_port = server.sockets[0].getsockname()[1]
    logger.info("Fake TCP login service listening on %s:%s.", LOCALHOST, bound_port)
    return server


async def run_tcp_service(
    *,
    port: int = DEFAULT_TCP_PORT,
    db_path: str | Path = DEFAULT_DB_PATH,
) -> None:
    """Run the TCP service until cancelled."""
    server = await start_tcp_service(port=port, db_path=db_path)
    async with server:
        await server.serve_forever()


def main(argv: list[str] | None = None) -> None:
    from config.loader import load_config
    from config.environment import database_path

    parser = argparse.ArgumentParser(description="Run the localhost TCP honeypot.")
    parser.add_argument("--config", type=Path)
    args = parser.parse_args(argv)
    settings = load_config(args.config)
    logging.basicConfig(level=getattr(logging, settings.log_level))
    asyncio.run(
        run_tcp_service(
            port=settings.tcp_port,
            db_path=database_path() or DEFAULT_DB_PATH,
        )
    )


if __name__ == "__main__":
    main()
