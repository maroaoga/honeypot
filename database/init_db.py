"""Command-line entry point for creating the SQLite database schema."""

import argparse
from pathlib import Path

from database.db import DEFAULT_DB_PATH, initialize_database


def main() -> None:
    parser = argparse.ArgumentParser(description="Initialize the honeypot database.")
    parser.add_argument(
        "database",
        nargs="?",
        type=Path,
        default=DEFAULT_DB_PATH,
        help=f"database file path (default: {DEFAULT_DB_PATH})",
    )
    args = parser.parse_args()
    initialize_database(args.database)
    print(f"Initialized database at {args.database}")


if __name__ == "__main__":
    main()
