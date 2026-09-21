"""Validated loading and lookup for configuration-driven compliance rules."""

from __future__ import annotations

import re
from pathlib import Path
from typing import Annotated, Self

import yaml
from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    StrictBool,
    StringConstraints,
    ValidationError,
    model_validator,
)

from cloud_security_governance.exceptions import ConfigurationError
from cloud_security_governance.models import CloudProvider, Severity

RuleIdentifier = Annotated[
    str,
    StringConstraints(strip_whitespace=True, min_length=1, max_length=256),
]
RuleName = Annotated[str, StringConstraints(strip_whitespace=True, min_length=1, max_length=512)]
RuleDescription = Annotated[
    str,
    StringConstraints(strip_whitespace=True, min_length=1, max_length=10_000),
]
_RULE_ID_PATTERN = re.compile(r"^[a-z0-9][a-z0-9_.-]*(?:\.\*)?$")


class RuleDefinition(BaseModel):
    """One validated AWS or Azure compliance rule definition."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    rule_id: RuleIdentifier
    name: RuleName
    cloud: CloudProvider
    severity: Severity
    description: RuleDescription
    enabled: StrictBool
    remediation_available: StrictBool

    @model_validator(mode="after")
    def validate_rule_id(self) -> Self:
        if not _RULE_ID_PATTERN.fullmatch(self.rule_id):
            raise ValueError("rule_id must be lowercase and may only use a trailing .* wildcard")
        if not self.rule_id.startswith(f"{self.cloud.value}."):
            raise ValueError("rule_id prefix must match cloud")
        return self

    def matches(self, finding_rule_id: str) -> bool:
        """Return whether this exact or template rule applies to a finding rule ID."""

        if self.rule_id.endswith(".*"):
            return finding_rule_id.startswith(self.rule_id[:-1])
        return finding_rule_id == self.rule_id


class RuleConfiguration(BaseModel):
    """Complete, duplicate-free compliance rule configuration."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    rules: tuple[RuleDefinition, ...] = Field(min_length=1)

    @model_validator(mode="after")
    def rule_ids_must_be_unique(self) -> Self:
        rule_ids = [rule.rule_id for rule in self.rules]
        if len(rule_ids) != len(set(rule_ids)):
            raise ValueError("rule IDs must be unique")
        return self

    def enabled_for_cloud(self, cloud: CloudProvider) -> tuple[RuleDefinition, ...]:
        """Return enabled rules for one cloud provider in configuration order."""

        return tuple(rule for rule in self.rules if rule.cloud is cloud and rule.enabled)

    def find(self, finding_rule_id: str) -> RuleDefinition | None:
        """Find an enabled exact or template rule for a scanner finding ID."""

        return next((rule for rule in self.rules if rule.enabled and rule.matches(finding_rule_id)), None)


def load_rules(path: str | Path = Path("config/rules.yaml")) -> RuleConfiguration:
    """Read and validate a YAML compliance-rule configuration."""

    rules_path = Path(path)
    try:
        raw = yaml.safe_load(rules_path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise ConfigurationError(f"Compliance rule file was not found: {rules_path}") from exc
    except (OSError, yaml.YAMLError) as exc:
        raise ConfigurationError(f"Unable to read compliance rule file: {rules_path}") from exc
    try:
        return RuleConfiguration.model_validate(raw)
    except ValidationError as exc:
        raise ConfigurationError(f"Compliance rule configuration is invalid: {rules_path}") from exc
