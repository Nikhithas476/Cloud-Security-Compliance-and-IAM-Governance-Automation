"""Mocked tests for read-only Defender for Cloud recommendation scanning."""

from __future__ import annotations

from datetime import UTC, datetime
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest
from azure.core.credentials import AccessToken
from azure.core.exceptions import HttpResponseError

from cloud_security_governance.azure import AzureDefenderScanner
from cloud_security_governance.azure.defender_scanner import DEFENDER_RECOMMENDATION_RULE_PREFIX
from cloud_security_governance.exceptions import AzureScanError
from cloud_security_governance.models import CloudProvider, Finding, Severity

SUBSCRIPTION_ID = "11111111-1111-4111-8111-111111111111"
RESOURCE_ID = (
    f"/subscriptions/{SUBSCRIPTION_ID}/resourceGroups/application/"
    "providers/Microsoft.Compute/virtualMachines/web01"
)
ASSESSMENT_NAME = "22222222-2222-4222-8222-222222222222"
ASSESSMENT_ID = f"{RESOURCE_ID}/providers/Microsoft.Security/assessments/{ASSESSMENT_NAME}"
NOW = datetime(2026, 9, 16, 12, 0, tzinfo=UTC)
EVALUATED_AT = datetime(2026, 9, 15, 12, 0, tzinfo=UTC)
TOKEN_TIME = 1_789_000_000.0


def assessment(
    *,
    status_code: str | None = "Unhealthy",
    severity: str | None = "High",
    include_metadata: bool = True,
    include_resource_details: bool = True,
) -> SimpleNamespace:
    metadata = (
        SimpleNamespace(
            display_name="Install endpoint protection",
            description="Endpoint protection is missing.",
            remediation_description="Install an endpoint protection solution.",
            severity=severity,
            policy_definition_id="/providers/Microsoft.Authorization/policyDefinitions/endpoint",
        )
        if include_metadata
        else None
    )
    status = (
        SimpleNamespace(
            code=status_code,
            cause="OffByPolicy",
            description="The resource is unhealthy.",
            first_evaluation_date=EVALUATED_AT,
            status_change_date=EVALUATED_AT,
        )
        if status_code is not None
        else None
    )
    return SimpleNamespace(
        id=ASSESSMENT_ID,
        name=ASSESSMENT_NAME,
        display_name=None,
        resource_details=SimpleNamespace(id=RESOURCE_ID) if include_resource_details else None,
        metadata=metadata,
        status=status,
    )


def build_scanner(items: list[SimpleNamespace]) -> tuple[AzureDefenderScanner, MagicMock]:
    credential = MagicMock()
    credential.get_token.return_value = AccessToken("mock-token", int(TOKEN_TIME + 3600))
    security = MagicMock()
    security.assessments.list.return_value = items
    scanner = AzureDefenderScanner(
        subscription_id=SUBSCRIPTION_ID,
        credential_factory=MagicMock(return_value=credential),
        security_client_factory=MagicMock(return_value=security),
        token_clock=MagicMock(return_value=TOKEN_TIME),
        scan_clock=MagicMock(return_value=NOW),
    )
    return scanner, security


def test_unhealthy_recommendation_generates_normalized_finding() -> None:
    scanner, security = build_scanner([assessment()])

    findings = scanner.scan()

    assert len(findings) == 1
    finding = findings[0]
    assert finding.rule_id == f"{DEFENDER_RECOMMENDATION_RULE_PREFIX}.{ASSESSMENT_NAME}"
    assert finding.title == "Install endpoint protection"
    assert finding.description == "Endpoint protection is missing."
    assert finding.severity is Severity.HIGH
    assert finding.resource.provider is CloudProvider.AZURE
    assert finding.resource.resource_id == RESOURCE_ID
    assert finding.resource.resource_type == "Microsoft.Compute/virtualMachines"
    assert finding.resource.name == "web01"
    assert finding.evidence["status"] == "Unhealthy"
    assert finding.evidence["defender_severity"] == "High"
    assert finding.evidence["first_evaluation_date"] == EVALUATED_AT.isoformat()
    assert finding.remediation_available is True
    assert finding.detected_at == NOW
    security.assessments.list.assert_called_once_with(f"/subscriptions/{SUBSCRIPTION_ID}")


@pytest.mark.parametrize("status", ["Healthy", "NotApplicable", None])
def test_non_actionable_or_missing_status_is_skipped(status: str | None) -> None:
    scanner, _ = build_scanner([assessment(status_code=status)])

    assert scanner.scan() == []


@pytest.mark.parametrize(
    ("defender_severity", "expected"),
    [
        ("High", Severity.HIGH),
        ("medium", Severity.MEDIUM),
        ("LOW", Severity.LOW),
        ("Informational", Severity.INFORMATIONAL),
        ("Unknown", Severity.INFORMATIONAL),
        (None, Severity.INFORMATIONAL),
    ],
)
def test_defender_severity_mapping(defender_severity: str | None, expected: Severity) -> None:
    assert AzureDefenderScanner.map_severity(defender_severity) is expected


def test_missing_metadata_uses_safe_fallbacks() -> None:
    scanner, _ = build_scanner([assessment(include_metadata=False)])

    finding = scanner.scan()[0]

    assert finding.title == f"Defender recommendation {ASSESSMENT_NAME}"
    assert finding.description == "The resource is unhealthy."
    assert finding.severity is Severity.INFORMATIONAL
    assert finding.remediation_available is False
    assert finding.evidence["defender_severity"] == "unspecified"


def test_missing_resource_details_uses_assessment_id() -> None:
    scanner, _ = build_scanner([assessment(include_resource_details=False)])

    assert scanner.scan()[0].resource.resource_id == RESOURCE_ID


def test_assessment_without_recoverable_resource_is_skipped() -> None:
    item = assessment(include_resource_details=False)
    item.id = None
    scanner, _ = build_scanner([item])

    assert scanner.scan() == []


def test_cross_subscription_resource_is_rejected() -> None:
    item = assessment()
    item.resource_details.id = item.resource_details.id.replace(
        SUBSCRIPTION_ID, "33333333-3333-4333-8333-333333333333"
    )
    scanner, _ = build_scanner([item])

    with pytest.raises(AzureScanError, match="outside the configured subscription"):
        scanner.scan()


def test_finding_round_trips_through_json() -> None:
    scanner, _ = build_scanner([assessment()])

    finding = scanner.scan()[0]

    assert Finding.model_validate_json(finding.model_dump_json()) == finding


def test_defender_api_error_is_sanitized() -> None:
    scanner, security = build_scanner([])
    response = MagicMock(status_code=403)
    error = HttpResponseError(message="sensitive Azure details", response=response)
    error.error = SimpleNamespace(code="AuthorizationFailed")
    security.assessments.list.side_effect = error

    with pytest.raises(AzureScanError, match="AuthorizationFailed") as raised:
        scanner.scan()

    assert "sensitive Azure details" not in str(raised.value)


def test_scanner_invokes_only_read_only_assessment_operations() -> None:
    scanner, security = build_scanner([assessment()])

    scanner.scan()

    method_names = {method_call[0] for method_call in security.method_calls}
    assert method_names == {"assessments.list"}
    assert not any(name.endswith((".create", ".delete", ".update")) for name in method_names)
