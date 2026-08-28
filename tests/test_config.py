from pathlib import Path

from cloud_security_governance.config import get_settings


def test_environment_overrides_yaml(monkeypatch, tmp_path: Path) -> None:
    config_file = tmp_path / "settings.yaml"
    config_file.write_text(
        "application:\n  name: YAML name\n  environment: test\nlogging:\n  level: WARNING\n",
        encoding="utf-8",
    )
    monkeypatch.setenv("CONFIG_FILE", str(config_file))
    monkeypatch.setenv("APP_NAME", "Environment name")
    get_settings.cache_clear()

    settings = get_settings()

    assert settings.app_name == "Environment name"
    assert settings.app_env == "test"
    assert settings.log_level == "WARNING"
    get_settings.cache_clear()

