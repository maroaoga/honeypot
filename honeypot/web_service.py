"""A fake Flask login page that is intended to run on localhost only."""

import logging
import argparse
import ipaddress
import sqlite3
from pathlib import Path

from flask import Flask, Response, abort, g, request

from adaptive.rules import SCAN_BANNER, get_source_controls
from database.db import DEFAULT_DB_PATH, create_event, create_session


LOCALHOST = "127.0.0.1"
DEFAULT_WEB_PORT = 8081
MAX_USERNAME_LENGTH = 256
MAX_REQUEST_BYTES = 16_384
DEFAULT_BANNER = "Sign in"

LOGIN_PAGE = """<!doctype html>
<html lang="en">
  <head><meta charset="utf-8"><title>Sign in</title></head>
  <body>
    <h1>Sign in</h1>
    <form method="post" action="/login">
      <label>Username <input name="username" autocomplete="username"></label>
      <label>Password <input name="password" type="password"
        autocomplete="current-password"></label>
      <button type="submit">Sign in</button>
    </form>
  </body>
</html>
"""

logger = logging.getLogger(__name__)


def create_app(db_path: str | Path = DEFAULT_DB_PATH) -> Flask:
    """Create the fake login app; callers control its database path for tests."""
    app = Flask(__name__)
    app.config["MAX_CONTENT_LENGTH"] = MAX_REQUEST_BYTES
    app.config["HONEYPOT_DB_PATH"] = str(db_path)

    @app.before_request
    def log_request() -> Response | None:
        remote_addr = request.remote_addr
        try:
            is_loopback = ipaddress.ip_address(remote_addr).is_loopback
        except (TypeError, ValueError):
            is_loopback = False
        if not is_loopback:
            abort(403)

        try:
            session_id = create_session(
                remote_addr,
                db_path=app.config["HONEYPOT_DB_PATH"],
            )
            create_event(
                session_id,
                "http_request",
                {
                    "method": request.method,
                    "path": request.path,
                    "content_type": request.content_type,
                },
                db_path=app.config["HONEYPOT_DB_PATH"],
            )
            controls = get_source_controls(
                remote_addr,
                db_path=app.config["HONEYPOT_DB_PATH"],
            )
        except (OSError, sqlite3.Error):
            app.logger.exception("Could not record incoming HTTP request.")
            return Response("Logging unavailable.\n", status=503, mimetype="text/plain")

        g.honeypot_session_id = session_id
        g.honeypot_banner = SCAN_BANNER if controls.scan_banner else DEFAULT_BANNER
        if controls.rate_limited:
            response = Response(
                "Rate limited. Try again later.\n",
                status=429,
                mimetype="text/plain",
            )
            response.headers["Retry-After"] = str(controls.retry_after_seconds)
            return response
        return None

    @app.route("/", methods=["GET"])
    @app.route("/login", methods=["GET", "POST"])
    def login() -> Response:
        if request.method == "POST":
            username = request.form.get("username", "")
            password = request.form.get("password", "")
            try:
                create_event(
                    g.honeypot_session_id,
                    "http_login_attempt",
                    {
                        "username": username[:MAX_USERNAME_LENGTH],
                        "username_truncated": len(username) > MAX_USERNAME_LENGTH,
                        "password_length": len(password),
                    },
                    db_path=app.config["HONEYPOT_DB_PATH"],
                )
            except sqlite3.Error:
                app.logger.exception("Could not record HTTP login attempt.")
                return Response(
                    "Logging unavailable.\n",
                    status=503,
                    mimetype="text/plain",
                )
            page = LOGIN_PAGE.replace(
                "<h1>Sign in</h1>",
                f"<h1>{g.honeypot_banner}</h1>",
            )
            return Response(page + "<p>Login failed.</p>", mimetype="text/html")

        page = LOGIN_PAGE.replace(
            "<h1>Sign in</h1>",
            f"<h1>{g.honeypot_banner}</h1>",
        )
        return Response(page, mimetype="text/html")

    return app


def run_web_service(
    *,
    port: int = DEFAULT_WEB_PORT,
    db_path: str | Path = DEFAULT_DB_PATH,
) -> None:
    """Run Flask's development server bound exclusively to localhost."""
    if type(port) is not int or not 0 <= port <= 65535:
        raise ValueError("port must be an integer from 0 through 65535.")
    app = create_app(db_path)
    app.run(host=LOCALHOST, port=port, debug=False, use_reloader=False)


def main(argv: list[str] | None = None) -> None:
    from config.environment import database_path
    from config.loader import load_config

    parser = argparse.ArgumentParser(description="Run the localhost web honeypot.")
    parser.add_argument("--config", type=Path)
    args = parser.parse_args(argv)
    settings = load_config(args.config)
    logging.basicConfig(level=getattr(logging, settings.log_level))
    run_web_service(
        port=settings.web_port,
        db_path=database_path() or DEFAULT_DB_PATH,
    )


if __name__ == "__main__":
    main()
