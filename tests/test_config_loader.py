import pytest

from config.loader import ConfigError, Settings, load_config


def test_loads_default_settings():
    assert load_config() == Settings(host="127.0.0.1", port=8080, log_level="INFO")


def test_loads_valid_custom_settings(tmp_path):
    settings_file = tmp_path / "settings.yaml"
    settings_file.write_text(
        "server:\n  host: '127.0.0.1'\n  port: 9090\n"
        "logging:\n  level: debug\n",
        encoding="utf-8",
    )

    assert load_config(settings_file) == Settings(
        host="127.0.0.1",
        port=9090,
        log_level="DEBUG",
    )


@pytest.mark.parametrize(
    ("contents", "message"),
    [
        ("[]", "YAML mapping"),
        ("server: []\nlogging: {}\n", "'server' mapping"),
        (
            "server:\n  host: 0.0.0.0\n  port: 8080\nlogging:\n  level: INFO\n",
            "server.host",
        ),
        (
            "server:\n  host: '127.0.0.1'\n  port: true\nlogging:\n  level: INFO\n",
            "server.port",
        ),
        (
            "server:\n  host: '127.0.0.1'\n  port: 8080\nlogging:\n  level: TRACE\n",
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
