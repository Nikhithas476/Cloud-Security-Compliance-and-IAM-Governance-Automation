"""Tests for validated configuration-driven compliance rules."""

from __future__ import annotations

from pathlib import Path

import pytest

from cloud_security_governance.exceptions import ConfigurationError
from cloud_security_governance.models import CloudProvider, Severity
from cloud_security_governance.rule_loader import RuleConfiguration, RuleDefinition, load_rules

DEFAULT_RULES_PATH = Path("config/rules.yaml")
EXPECTED_RULE_IDS = {
    "aws.iam.policy.wildcard-action",
    "aws.iam.policy.wildcard-resource",
    "aws.iam.user.mfa-enabled",
    "aws.iam.access-key.stale",
    "aws.iam.root.access-key",
    "aws.s3.bucket.encryption-enabled",
    "aws.ec2.ebs.volume-encryption-enabled",
    "aws.cloudtrail.trail.exists",
    "aws.cloudtrail.logging.enabled",
    "aws.config.recorder.enabled",
    "aws.config.rule.compliant",
    "azure.rbac.owner-assignment",
    "azure.rbac.contributor-assignment",
    "azure.rbac.subscription-privileged-assignment",
    "azure.rbac.excessive-permissions",
    "azure.policy.non-compliant-resource",
    "azure.storage.encryption.service-enabled",
    "azure.storage.encryption.infrastructure-enabled",
    "azure.storage.encryption.customer-managed-key",
    "azure.defender.recommendation.*",
}


def valid_rule(**overrides: object) -> dict[str, object]:
    rule: dict[str, object] = {
        "rule_id": "aws.test.control-enabled",
        "name": "Test control",
        "cloud": "aws",
        "severity": "high",
        "description": "Detects a test compliance violation.",
        "enabled": True,
        "remediation_available": False,
    }
    rule.update(overrides)
    return rule


def write_rules(path: Path, rules: list[dict[str, object]]) -> None:
    import yaml

    path.write_text(yaml.safe_dump({"rules": rules}, sort_keys=False), encoding="utf-8")


def test_default_rule_configuration_loads_all_implemented_rules() -> None:
    configuration = load_rules(DEFAULT_RULES_PATH)

    assert isinstance(configuration, RuleConfiguration)
    assert {rule.rule_id for rule in configuration.rules} == EXPECTED_RULE_IDS
    assert len(configuration.enabled_for_cloud(CloudProvider.AWS)) == 11
    assert len(configuration.enabled_for_cloud(CloudProvider.AZURE)) == 9
    assert all(rule.enabled for rule in configuration.rules)
    assert configuration.find("aws.iam.policy.wildcard-action") is not None


def test_rule_fields_are_strongly_typed() -> None:
    rule = RuleDefinition.model_validate(valid_rule())

    assert rule.cloud is CloudProvider.AWS
    assert rule.severity is Severity.HIGH
    assert rule.enabled is True
    assert rule.remediation_available is False


def test_dynamic_defender_template_matches_assessment_rule_ids() -> None:
    configuration = load_rules(DEFAULT_RULES_PATH)

    rule = configuration.find("azure.defender.recommendation.22222222-2222-4222-8222-222222222222")

    assert rule is not None
    assert rule.rule_id == "azure.defender.recommendation.*"
    assert rule.severity is Severity.INFORMATIONAL
    assert configuration.find("azure.defender.unrelated") is None


def test_disabled_rules_are_excluded_from_lookup_and_enabled_cloud_rules(tmp_path: Path) -> None:
    path = tmp_path / "rules.yaml"
    write_rules(path, [valid_rule(enabled=False)])

    configuration = load_rules(path)

    assert configuration.enabled_for_cloud(CloudProvider.AWS) == ()
    assert configuration.find("aws.test.control-enabled") is None


@pytest.mark.parametrize(
    "rule",
    [
        valid_rule(cloud="gcp"),
        valid_rule(severity="urgent"),
        valid_rule(rule_id="azure.test.control", cloud="aws"),
        valid_rule(rule_id="AWS.TEST.CONTROL"),
        valid_rule(rule_id="aws.*.invalid"),
        valid_rule(name=" "),
        valid_rule(description=""),
        valid_rule(enabled="yes"),
        valid_rule(remediation_available=None),
        valid_rule(unexpected_field=True),
    ],
)
def test_invalid_rule_values_are_rejected(tmp_path: Path, rule: dict[str, object]) -> None:
    path = tmp_path / "rules.yaml"
    write_rules(path, [rule])

    with pytest.raises(ConfigurationError, match="configuration is invalid"):
        load_rules(path)


def test_duplicate_rule_ids_are_rejected(tmp_path: Path) -> None:
    path = tmp_path / "rules.yaml"
    write_rules(path, [valid_rule(), valid_rule(name="Duplicate")])

    with pytest.raises(ConfigurationError, match="configuration is invalid"):
        load_rules(path)


@pytest.mark.parametrize(
    "content",
    [
        "- not-a-mapping\n",
        "rules: []\n",
        "unknown: []\n",
        "rules: [\n",
    ],
)
def test_invalid_file_structures_are_rejected(tmp_path: Path, content: str) -> None:
    path = tmp_path / "rules.yaml"
    path.write_text(content, encoding="utf-8")

    with pytest.raises(ConfigurationError):
        load_rules(path)


def test_missing_rule_file_is_reported(tmp_path: Path) -> None:
    with pytest.raises(ConfigurationError, match="was not found"):
        load_rules(tmp_path / "missing.yaml")
