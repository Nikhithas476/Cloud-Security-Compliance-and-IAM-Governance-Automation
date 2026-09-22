"""Tests for provider-neutral compliance rule evaluation."""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path
from unittest.mock import MagicMock

import pytest

from cloud_security_governance import ComplianceEngine, RuleEvaluator
from cloud_security_governance.exceptions import ConfigurationError
from cloud_security_governance.models import (
    CloudProvider,
    ComplianceReport,
    ComplianceStatus,
    Finding,
    Resource,
    Severity,
)
from cloud_security_governance.rule_loader import RuleConfiguration, RuleDefinition

NOW = datetime(2026, 9, 22, 12, 0, tzinfo=UTC)
AWS_ACCOUNT_ID = "123456789012"
AZURE_SUBSCRIPTION_ID = "11111111-1111-4111-8111-111111111111"


def rule(
    rule_id: str,
    cloud: CloudProvider,
    *,
    enabled: bool = True,
    severity: Severity = Severity.HIGH,
    remediation_available: bool = True,
) -> RuleDefinition:
    return RuleDefinition(
        rule_id=rule_id,
        name=f"Rule {rule_id}",
        cloud=cloud,
        severity=severity,
        description=f"Compliance requirement for {rule_id}.",
        enabled=enabled,
        remediation_available=remediation_available,
    )


def finding(rule_id: str, cloud: CloudProvider = CloudProvider.AWS, *, suffix: str = "one") -> Finding:
    if cloud is CloudProvider.AWS:
        resource = Resource(
            resource_id=f"arn:aws:s3:::bucket-{suffix}",
            provider=cloud,
            account_id=AWS_ACCOUNT_ID,
            resource_type="s3-bucket",
            name=f"bucket-{suffix}",
        )
    else:
        resource = Resource(
            resource_id=(
                f"/subscriptions/{AZURE_SUBSCRIPTION_ID}/resourceGroups/test/"
                f"providers/Microsoft.Compute/virtualMachines/vm-{suffix}"
            ),
            provider=cloud,
            account_id=AZURE_SUBSCRIPTION_ID,
            resource_type="Microsoft.Compute/virtualMachines",
            name=f"vm-{suffix}",
        )
    return Finding(
        rule_id=rule_id,
        resource=resource,
        title="Scanner finding",
        description="The scanner detected a compliance violation.",
        severity=Severity.CRITICAL,
        detected_at=NOW,
    )


def engine(configuration: RuleConfiguration) -> tuple[ComplianceEngine, MagicMock]:
    loader = MagicMock(return_value=configuration)
    return (
        ComplianceEngine(
            rules_path=Path("test-rules.yaml"),
            rule_loader=loader,
            clock=MagicMock(return_value=NOW),
        ),
        loader,
    )


def test_rule_evaluator_marks_matching_findings_non_compliant() -> None:
    definition = rule("aws.s3.bucket.encryption-enabled", CloudProvider.AWS)
    scanner_finding = finding(definition.rule_id)

    result = RuleEvaluator(definition).evaluate([scanner_finding], evaluated_at=NOW)

    assert result.status is ComplianceStatus.NON_COMPLIANT
    assert result.findings == [scanner_finding]
    assert result.finding_count == 1
    assert result.severity is Severity.HIGH
    assert result.remediation_available is True


def test_rule_evaluator_marks_absent_violations_compliant() -> None:
    definition = rule("aws.s3.bucket.encryption-enabled", CloudProvider.AWS)

    result = RuleEvaluator(definition).evaluate([], evaluated_at=NOW)

    assert result.status is ComplianceStatus.COMPLIANT
    assert result.finding_count == 0


def test_rule_evaluator_does_not_duplicate_cloud_specific_detection_logic() -> None:
    definition = rule("aws.s3.bucket.encryption-enabled", CloudProvider.AWS)
    unrelated = finding("aws.iam.user.mfa-enabled")
    wrong_cloud = finding(definition.rule_id, CloudProvider.AZURE)

    result = RuleEvaluator(definition).evaluate([unrelated, wrong_cloud], evaluated_at=NOW)

    assert result.status is ComplianceStatus.COMPLIANT
    assert result.findings == []


def test_engine_loads_enabled_rules_and_builds_normalized_report() -> None:
    configuration = RuleConfiguration(
        rules=(
            rule("aws.s3.bucket.encryption-enabled", CloudProvider.AWS),
            rule("azure.policy.non-compliant-resource", CloudProvider.AZURE),
            rule("aws.iam.user.mfa-enabled", CloudProvider.AWS, enabled=False),
        )
    )
    evaluator, loader = engine(configuration)
    scanner_finding = finding("aws.s3.bucket.encryption-enabled")

    report = evaluator.evaluate([scanner_finding])

    loader.assert_called_once_with(Path("test-rules.yaml"))
    assert isinstance(report, ComplianceReport)
    assert [result.rule_id for result in report.results] == [
        "aws.s3.bucket.encryption-enabled",
        "azure.policy.non-compliant-resource",
    ]
    assert [result.status for result in report.results] == [
        ComplianceStatus.NON_COMPLIANT,
        ComplianceStatus.COMPLIANT,
    ]
    assert report.rules_evaluated == 2
    assert report.compliant_rules == 1
    assert report.non_compliant_rules == 1
    assert report.matched_findings == 1
    assert report.unmatched_findings == []
    assert report.evaluated_at == NOW


def test_engine_groups_multiple_findings_under_one_rule() -> None:
    definition = rule("aws.s3.bucket.encryption-enabled", CloudProvider.AWS)
    evaluator, _ = engine(RuleConfiguration(rules=(definition,)))

    report = evaluator.evaluate(
        [finding(definition.rule_id, suffix="one"), finding(definition.rule_id, suffix="two")]
    )

    assert report.results[0].finding_count == 2
    assert report.matched_findings == 2
    assert report.non_compliant_rules == 1


def test_dynamic_rule_template_matches_defender_recommendation() -> None:
    template = rule(
        "azure.defender.recommendation.*",
        CloudProvider.AZURE,
        severity=Severity.INFORMATIONAL,
    )
    evaluator, _ = engine(RuleConfiguration(rules=(template,)))
    scanner_finding = finding(
        "azure.defender.recommendation.22222222-2222-4222-8222-222222222222",
        CloudProvider.AZURE,
    )

    report = evaluator.evaluate([scanner_finding])

    assert report.results[0].rule_id == "azure.defender.recommendation.*"
    assert report.results[0].status is ComplianceStatus.NON_COMPLIANT
    assert report.results[0].findings == [scanner_finding]


def test_exact_rule_takes_precedence_over_wildcard_template() -> None:
    exact_id = "azure.defender.recommendation.special"
    configuration = RuleConfiguration(
        rules=(
            rule("azure.defender.recommendation.*", CloudProvider.AZURE),
            rule(exact_id, CloudProvider.AZURE, severity=Severity.CRITICAL),
        )
    )
    evaluator, _ = engine(configuration)

    report = evaluator.evaluate([finding(exact_id, CloudProvider.AZURE)])

    by_id = {result.rule_id: result for result in report.results}
    assert by_id[exact_id].status is ComplianceStatus.NON_COMPLIANT
    assert by_id[exact_id].finding_count == 1
    assert by_id["azure.defender.recommendation.*"].status is ComplianceStatus.COMPLIANT


def test_unmatched_and_disabled_rule_findings_are_preserved() -> None:
    disabled_id = "aws.iam.user.mfa-enabled"
    configuration = RuleConfiguration(
        rules=(
            rule("aws.s3.bucket.encryption-enabled", CloudProvider.AWS),
            rule(disabled_id, CloudProvider.AWS, enabled=False),
        )
    )
    evaluator, _ = engine(configuration)
    disabled_finding = finding(disabled_id)
    unknown_finding = finding("aws.unknown.control", suffix="unknown")

    report = evaluator.evaluate([disabled_finding, unknown_finding])

    assert report.unmatched_findings == [disabled_finding, unknown_finding]
    assert report.matched_findings == 0
    assert report.results[0].status is ComplianceStatus.COMPLIANT


def test_report_round_trips_through_json() -> None:
    definition = rule("aws.s3.bucket.encryption-enabled", CloudProvider.AWS)
    evaluator, _ = engine(RuleConfiguration(rules=(definition,)))

    report = evaluator.evaluate([finding(definition.rule_id)])
    restored = ComplianceReport.model_validate_json(report.model_dump_json())

    assert restored == report
    assert restored.evaluation_id == report.evaluation_id


def test_disabled_rule_cannot_be_evaluated_directly() -> None:
    with pytest.raises(ConfigurationError, match="enabled"):
        RuleEvaluator(rule("aws.test.disabled", CloudProvider.AWS, enabled=False))


def test_naive_evaluation_timestamp_is_rejected() -> None:
    definition = rule("aws.s3.bucket.encryption-enabled", CloudProvider.AWS)

    with pytest.raises(ConfigurationError, match="timezone"):
        RuleEvaluator(definition).evaluate(
            [], evaluated_at=datetime(2026, 9, 22, 12, 0)  # noqa: DTZ001
        )


def test_rule_loader_failure_propagates_without_evaluating_findings() -> None:
    loader = MagicMock(side_effect=ConfigurationError("invalid rules"))
    evaluator = ComplianceEngine(rule_loader=loader, clock=MagicMock(return_value=NOW))

    with pytest.raises(ConfigurationError, match="invalid rules"):
        evaluator.evaluate([finding("aws.s3.bucket.encryption-enabled")])
