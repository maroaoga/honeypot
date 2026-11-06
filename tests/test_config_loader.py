import pytest

from config.loader import ConfigError, Settings, load_config


def test_loads_default_settings():
    assert load_config() == Settings(
        host="127.0.0.1",
        tcp_port=8022,
        web_port=8081,
        log_level="INFO",
    )


def test_loads_valid_custom_settings(tmp_path):
    settings_file = tmp_path / "settings.yaml"
    settings_file.write_text(
        "server:\n  host: '127.0.0.1'\n  tcp_port: 9090\n  web_port: 9091\n"
        "logging:\n  level: debug\n",
        encoding="utf-8",
    )

    assert load_config(settings_file) == Settings(
        host="127.0.0.1",
        tcp_port=9090,
        web_port=9091,
        log_level="DEBUG",
    )


@pytest.mark.parametrize(
    ("contents", "message"),
    [
        ("[]", "YAML mapping"),
        ("server: []\nlogging: {}\n", "'server' mapping"),
        (
            "server:\n  host: 0.0.0.0\n  tcp_port: 8022\n  web_port: 8081\nlogging:\n  level: INFO\n",
            "server.host",
        ),
        (
            "server:\n  host: '127.0.0.1'\n  tcp_port: true\n  web_port: 8081\nlogging:\n  level: INFO\n",
            "server.tcp_port",
        ),
        (
            "server:\n  host: '127.0.0.1'\n  tcp_port: 8022\n  web_port: 8081\nlogging:\n  level: TRACE\n",
            "logging.level",
        ),
        ("server: [\n", "Invalid YAML"),
    ],
)
def test_rejects_invalid_settings(tmp_path, contents, message):
    settings_file = tmp_path / "settings.yaml"
    settings_file.write_text(contents, encoding="utf-8")

    with pytest.raises(ConfigError, match=message):
        load_config(settings_file)


def test_missing_settings_file_has_clear_error(tmp_path):
    with pytest.raises(ConfigError, match="Unable to read settings file"):
        load_config(tmp_path / "missing.yaml")


def test_rejects_duplicate_service_ports(tmp_path):
    settings_file = tmp_path / "settings.yaml"
    settings_file.write_text(
        "server:\n  host: '127.0.0.1'\n  tcp_port: 8080\n  web_port: 8080\n"
        "logging:\n  level: INFO\n",
        encoding="utf-8",
    )

    with pytest.raises(ConfigError, match="must be different"):
        load_config(settings_file)


def test_loads_dotenv_values_without_overriding_exported_values(tmp_path, monkeypatch):
    from config.environment import load_dotenv
    import os

    env_file = tmp_path / ".env"
    env_file.write_text(
        "# local settings\nHONEYPOT_TEST_FROM_FILE='hello world'\n"
        "HONEYPOT_TEST_EXPORTED=file-value\n",
        encoding="utf-8",
    )
    monkeypatch.setenv("HONEYPOT_TEST_EXPORTED", "shell-value")
    original_value = os.environ.get("HONEYPOT_TEST_FROM_FILE")
    try:
        load_dotenv(env_file)
        assert os.environ["HONEYPOT_TEST_FROM_FILE"] == "hello world"
        assert os.environ["HONEYPOT_TEST_EXPORTED"] == "shell-value"
    finally:
        if original_value is None:
            os.environ.pop("HONEYPOT_TEST_FROM_FILE", None)
        else:
            os.environ["HONEYPOT_TEST_FROM_FILE"] = original_value


def test_rejects_invalid_dotenv_line(tmp_path):
    from config.environment import load_dotenv

    env_file = tmp_path / ".env"
    env_file.write_text("not an assignment\n", encoding="utf-8")

    with pytest.raises(ValueError, match="Invalid environment assignment"):
        load_dotenv(env_file)
