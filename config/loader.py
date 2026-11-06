"""Load and validate the project's YAML settings."""

from dataclasses import dataclass
import os
from pathlib import Path

import yaml

from config.environment import DEFAULT_ENV_PATH, load_dotenv


class ConfigError(ValueError):
    """Raised when the settings file cannot be loaded or validated."""


@dataclass(frozen=True)
class Settings:
    host: str
    tcp_port: int
    web_port: int
    log_level: str


def _validate_port(value: object, name: str) -> int:
    if type(value) is not int or not 1 <= value <= 65535:
        raise ConfigError(f"server.{name} must be an integer from 1 through 65535.")
    return value


def load_config(
    path: str | Path | None = None,
    *,
    env_path: str | Path = DEFAULT_ENV_PATH,
) -> Settings:
    """Load settings from a YAML file, defaulting to config/settings.yaml."""
    load_dotenv(env_path)
    configured_path = os.environ.get("HONEYPOT_CONFIG_PATH")
    config_path = (
        Path(path)
        if path is not None
        else Path(configured_path)
        if configured_path
        else Path(__file__).with_name("settings.yaml")
    )

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

    tcp_port = _validate_port(server.get("tcp_port"), "tcp_port")
    web_port = _validate_port(server.get("web_port"), "web_port")
    if tcp_port == web_port:
        raise ConfigError("server.tcp_port and server.web_port must be different.")
    if "HONEYPOT_TCP_PORT" in os.environ:
        try:
            configured_tcp_port = int(os.environ["HONEYPOT_TCP_PORT"])
        except ValueError as exc:
            raise ConfigError("HONEYPOT_TCP_PORT must be an integer from 1 through 65535.") from exc
        tcp_port = _validate_port(configured_tcp_port, "tcp_port")
    if "HONEYPOT_WEB_PORT" in os.environ:
        try:
            configured_web_port = int(os.environ["HONEYPOT_WEB_PORT"])
        except ValueError as exc:
            raise ConfigError("HONEYPOT_WEB_PORT must be an integer from 1 through 65535.") from exc
        web_port = _validate_port(configured_web_port, "web_port")
    if tcp_port == web_port:
        raise ConfigError("TCP and web service ports must be different.")

    log_level = logging.get("level")
    if not isinstance(log_level, str) or log_level.upper() not in {
        "DEBUG",
        "INFO",
        "WARNING",
        "ERROR",
        "CRITICAL",
    }:
        raise ConfigError("logging.level must be a standard logging level.")

    return Settings(
        host=host,
        tcp_port=tcp_port,
        web_port=web_port,
        log_level=log_level.upper(),
    )
