import sqlite3
import sys

from database.init_db import main


def test_init_db_cli_creates_requested_database(tmp_path, monkeypatch, capsys):
    database_path = tmp_path / "cli.db"
    monkeypatch.setattr(sys, "argv", ["init_db", str(database_path)])

    main()

    assert database_path.is_file()
    with sqlite3.connect(database_path) as connection:
        tables = {
            row[0]
            for row in connection.execute(
                "SELECT name FROM sqlite_master WHERE type = ?",
                ("table",),
            )
        }
    assert {"sessions", "events", "alerts", "adaptive_actions"} <= tables
    assert str(database_path) in capsys.readouterr().out
