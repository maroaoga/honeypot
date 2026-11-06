"""Command-line entry point for creating the SQLite database schema."""

import argparse
from pathlib import Path

from config.environment import database_path
from database.db import DEFAULT_DB_PATH, initialize_database


def main(argv: list[str] | None = None) -> None:
    default_path = database_path() or DEFAULT_DB_PATH
    parser = argparse.ArgumentParser(description="Initialize the honeypot database.")
    parser.add_argument(
        "database",
        nargs="?",
        type=Path,
        default=default_path,
        help=f"database file path (default: {default_path})",
    )
    args = parser.parse_args(argv)
    initialize_database(args.database)
    print(f"Initialized database at {args.database}")


if __name__ == "__main__":
    main()
