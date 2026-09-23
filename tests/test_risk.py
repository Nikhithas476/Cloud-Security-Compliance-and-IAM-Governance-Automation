"""Tests for deterministic multi-cloud risk scoring."""

from __future__ import annotations

from uuid import UUID

import pytest
from pydantic import ValidationError

from cloud_security_governance import RiskCalculator, RiskScore, RiskWeights
from cloud_security_governance.models import CloudProvider, Finding, Resource, Severity

AWS_ACCOUNT_ID = "123456789012"
AZURE_SUBSCRIPTION_ID = "11111111-1111-4111-8111-111111111111"


def finding(
    severity: Severity,
    cloud: CloudProvider,
    sequence: int,
    *,
    finding_id: UUID | None = None,
) -> Finding:
    if cloud is CloudProvider.AWS:
        account_id = AWS_ACCOUNT_ID
        resource_id = f"arn:aws:s3:::bucket-{sequence}"
        resource_type = "s3-bucket"
    else:
        account_id = AZURE_SUBSCRIPTION_ID
        resource_id = (
            f"/subscriptions/{account_id}/resourceGroups/test/providers/"
            f"Microsoft.Storage/storageAccounts/storage{sequence}"
        )
        resource_type = "Microsoft.Storage/storageAccounts"
    values = {
        "rule_id": f"{cloud.value}.test.rule-{sequence}",
        "resource": Resource(
            resource_id=resource_id,
            provider=cloud,
            account_id=account_id,
            resource_type=resource_type,
            name=f"resource-{sequence}",
        ),
        "title": "Risk test finding",
        "description": "A normalized finding used to test risk scoring.",
        "severity": severity,
    }
    if finding_id is not None:
        values["finding_id"] = finding_id
    return Finding.model_validate(values)


def test_empty_findings_have_zero_risk_and_distribution() -> None:
    result = RiskCalculator().calculate([])

    assert result.overall_risk_score == 0
    assert result.aws_risk_score == 0
    assert result.azure_risk_score == 0
    assert result.findings_scored == 0
    assert result.severity_distribution.model_dump() == {
        "critical": 0,
        "high": 0,
        "medium": 0,
        "low": 0,
        "informational": 0,
    }


def test_default_weights_calculate_overall_and_cloud_scores() -> None:
    findings = [
        finding(Severity.CRITICAL, CloudProvider.AWS, 1),
        finding(Severity.HIGH, CloudProvider.AWS, 2),
        finding(Severity.MEDIUM, CloudProvider.AZURE, 3),
        finding(Severity.LOW, CloudProvider.AZURE, 4),
        finding(Severity.INFORMATIONAL, CloudProvider.AZURE, 5),
    ]

    result = RiskCalculator().calculate(findings)

    assert result.overall_risk_score == 41
    assert result.aws_risk_score == 35
    assert result.azure_risk_score == 6
    assert result.findings_scored == 5
    assert result.severity_distribution.model_dump() == {
        "critical": 1,
        "high": 1,
        "medium": 1,
        "low": 1,
        "informational": 1,
    }


def test_scores_are_capped_at_one_hundred() -> None:
    findings = [
        *(finding(Severity.CRITICAL, CloudProvider.AWS, index) for index in range(1, 6)),
        finding(Severity.CRITICAL, CloudProvider.AZURE, 6),
    ]

    result = RiskCalculator().calculate(findings)

    assert result.overall_risk_score == 100
    assert result.aws_risk_score == 100
    assert result.azure_risk_score == 25
    assert result.findings_scored == 6


def test_configurable_weights_are_applied_to_every_score() -> None:
    calculator = RiskCalculator(
        {"critical": 40, "high": 20, "medium": 8, "low": 2}
    )
    findings = [
        finding(Severity.HIGH, CloudProvider.AWS, 1),
        finding(Severity.MEDIUM, CloudProvider.AZURE, 2),
        finding(Severity.LOW, CloudProvider.AZURE, 3),
    ]

    result = calculator.calculate(findings)

    assert result.overall_risk_score == 30
    assert result.aws_risk_score == 20
    assert result.azure_risk_score == 10


def test_zero_weights_are_supported() -> None:
    weights = RiskWeights(critical=0, high=0, medium=0, low=0)

    result = RiskCalculator(weights).calculate(
        [finding(Severity.CRITICAL, CloudProvider.AWS, 1)]
    )

    assert result.overall_risk_score == 0
    assert result.findings_scored == 1
    assert result.severity_distribution.critical == 1


def test_duplicate_finding_id_is_counted_once() -> None:
    original = finding(Severity.HIGH, CloudProvider.AWS, 1)
    duplicate = original.model_copy(deep=True)

    result = RiskCalculator().calculate([original, duplicate])

    assert result.overall_risk_score == 10
    assert result.findings_scored == 1
    assert result.severity_distribution.high == 1


def test_different_findings_for_same_rule_are_counted_separately() -> None:
    first = finding(Severity.HIGH, CloudProvider.AWS, 1)
    second = finding(Severity.HIGH, CloudProvider.AWS, 2)
    second.rule_id = first.rule_id

    result = RiskCalculator().calculate([first, second])

    assert result.overall_risk_score == 20
    assert result.findings_scored == 2


def test_scoring_is_order_independent_and_accepts_generators() -> None:
    findings = [
        finding(Severity.LOW, CloudProvider.AWS, 1),
        finding(Severity.CRITICAL, CloudProvider.AZURE, 2),
        finding(Severity.MEDIUM, CloudProvider.AWS, 3),
    ]
    calculator = RiskCalculator()

    forward = calculator.calculate(item for item in findings)
    reverse = calculator.calculate(item for item in reversed(findings))

    assert forward == reverse


def test_risk_score_round_trips_through_json() -> None:
    result = RiskCalculator().calculate(
        [finding(Severity.CRITICAL, CloudProvider.AZURE, 1)]
    )

    assert RiskScore.model_validate_json(result.model_dump_json()) == result


@pytest.mark.parametrize(
    "weights",
    [
        {"critical": -1},
        {"high": 101},
        {"medium": 1.5},
        {"low": True},
        {"informational": 1},
    ],
)
def test_invalid_weight_configuration_is_rejected(weights: dict[str, object]) -> None:
    with pytest.raises(ValidationError):
        RiskCalculator(weights)
