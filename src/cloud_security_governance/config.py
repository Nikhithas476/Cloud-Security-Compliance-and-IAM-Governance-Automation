"""Application configuration loaded from safe YAML defaults and environment variables."""

from __future__ import annotations

import os
from functools import lru_cache
from pathlib import Path
from typing import Any

import yaml
from pydantic import BaseModel, ConfigDict, Field, ValidationError

from cloud_security_governance.exceptions import ConfigurationError


class Settings(BaseModel):
    """Validated runtime settings with non-secret defaults."""

    model_config = ConfigDict(extra="forbid")

    app_name: str = "Cloud Security Compliance and IAM Governance Automation"
    app_env: str = "development"
    log_level: str = "INFO"
    aws_region: str = "us-east-1"
    azure_subscription_id: str = ""
    config_file: Path = Field(default=Path("config/default.yaml"), exclude=True)


def _yaml_values(path: Path) -> dict[str, Any]:
    if not path.exists():
        return {}
    try:
        raw = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    except (OSError, yaml.YAMLError) as exc:
        raise ConfigurationError(f"Unable to read configuration file: {path}") from exc
    if not isinstance(raw, dict):
        raise ConfigurationError(f"Configuration root must be a mapping: {path}")
    application = raw.get("application", {})
    logging_config = raw.get("logging", {})
    cloud = raw.get("cloud", {})
    return {
        "app_name": application.get("name"),
        "app_env": application.get("environment"),
        "log_level": logging_config.get("level"),
        "aws_region": cloud.get("aws_region"),
        "azure_subscription_id": cloud.get("azure_subscription_id"),
    }


@lru_cache
def get_settings() -> Settings:
    """Load settings, allowing environment variables to override YAML defaults."""

    config_file = Path(os.getenv("CONFIG_FILE", "config/default.yaml"))
    values = {key: value for key, value in _yaml_values(config_file).items() if value is not None}
    environment_values = {
        "app_name": os.getenv("APP_NAME"),
        "app_env": os.getenv("APP_ENV"),
        "log_level": os.getenv("LOG_LEVEL"),
        "aws_region": os.getenv("AWS_REGION"),
        "azure_subscription_id": os.getenv("AZURE_SUBSCRIPTION_ID"),
    }
    values.update({key: value for key, value in environment_values.items() if value is not None})
    values["config_file"] = config_file
    try:
        return Settings.model_validate(values)
    except ValidationError as exc:
        raise ConfigurationError("Application configuration is invalid") from exc

