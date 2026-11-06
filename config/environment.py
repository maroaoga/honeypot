"""Load the project's optional local environment settings without dependencies."""

import logging
import os
import re
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_ENV_PATH = PROJECT_ROOT / ".env"
_ENV_NAME = re.compile(r"[A-Za-z_][A-Za-z0-9_]*\Z")
logger = logging.getLogger(__name__)


def load_dotenv(path: str | Path = DEFAULT_ENV_PATH) -> None:
    """Load simple KEY=VALUE lines without overriding exported variables."""
    env_path = Path(path)
    try:
        contents = env_path.read_text(encoding="utf-8")
    except FileNotFoundError:
        return
    except OSError:
        logger.exception("Could not read environment file '%s'.", env_path)
        raise

    for line_number, raw_line in enumerate(contents.splitlines(), start=1):
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("export "):
            line = line[len("export ") :].lstrip()
        name, separator, value = line.partition("=")
        name = name.strip()
        if not separator or not _ENV_NAME.fullmatch(name):
            raise ValueError(
                f"Invalid environment assignment on line {line_number} "
                f"of '{env_path}'."
            )
        value = value.strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in {"'", '"'}:
            value = value[1:-1]
        elif " #" in value:
            value = value.split(" #", maxsplit=1)[0].rstrip()
        os.environ.setdefault(name, value)


def database_path() -> str | Path | None:
    """Return the optional database override after loading local env values."""
    load_dotenv()
    return os.environ.get("HONEYPOT_DB_PATH")
