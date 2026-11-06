"""Load and validate the project's YAML settings."""

from dataclasses import dataclass
from pathlib import Path

import yaml


class ConfigError(ValueError):
    """Raised when the settings file cannot be loaded or validated."""


@dataclass(frozen=True)
class Settings:
    host: str
    port: int
    log_level: str


def load_config(path: str | Path | None = None) -> Settings:
    """Load settings from a YAML file, defaulting to config/settings.yaml."""
    config_path = Path(path) if path is not None else Path(__file__).with_name("settings.yaml")

    try:
        contents = config_path.read_text(encoding="utf-8")
    except OSError as exc:
        raise ConfigError(f"Unable to read settings file '{config_path}': {exc}") from exc

    try:
        data = yaml.safe_load(contents)
    except yaml.YAMLError as exc:
        raise ConfigError(f"Invalid YAML in settings file '{config_path}': {exc}") from exc

    if not isinstance(data, dict):
        raise ConfigError("Settings must contain a YAML mapping.")

    server = data.get("server")
    logging = data.get("logging")
    if not isinstance(server, dict):
        raise ConfigError("Settings must include a 'server' mapping.")
    if not isinstance(logging, dict):
        raise ConfigError("Settings must include a 'logging' mapping.")

    host = server.get("host")
    if host != "127.0.0.1":
        raise ConfigError("server.host must be '127.0.0.1' so the service stays local.")

    port = server.get("port")
    if type(port) is not int or not 1 <= port <= 65535:
        raise ConfigError("server.port must be an integer from 1 through 65535.")

    log_level = logging.get("level")
    if not isinstance(log_level, str) or log_level.upper() not in {
        "DEBUG",
        "INFO",
        "WARNING",
        "ERROR",
        "CRITICAL",
    }:
        raise ConfigError("logging.level must be a standard logging level.")

    return Settings(host=host, port=port, log_level=log_level.upper())
