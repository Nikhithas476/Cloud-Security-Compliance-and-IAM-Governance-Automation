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


def test_aws_authentication_environment_settings(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.setenv("CONFIG_FILE", str(tmp_path / "missing.yaml"))
    monkeypatch.setenv("AWS_REGION", "eu-central-1")
    monkeypatch.setenv("AWS_PROFILE", "security-audit")
    monkeypatch.setenv(
        "AWS_ROLE_ARN", "arn:aws:iam::123456789012:role/SecurityAuditRole"
    )
    get_settings.cache_clear()

    settings = get_settings()

    assert settings.aws_region == "eu-central-1"
    assert settings.aws_profile == "security-audit"
    assert settings.aws_role_arn == "arn:aws:iam::123456789012:role/SecurityAuditRole"
    get_settings.cache_clear()
