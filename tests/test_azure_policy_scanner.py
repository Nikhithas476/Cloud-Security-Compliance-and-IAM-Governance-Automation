"""Mocked tests for read-only Azure Policy compliance scanning."""

from __future__ import annotations

from datetime import UTC, datetime
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest
from azure.core.credentials import AccessToken
from azure.core.exceptions import HttpResponseError

from cloud_security_governance.azure import AzurePolicyScanner
from cloud_security_governance.azure.policy_scanner import NON_COMPLIANT_POLICY_RULE_ID
from cloud_security_governance.exceptions import AzureScanError
from cloud_security_governance.models import CloudProvider, Finding, Severity

SUBSCRIPTION_ID = "11111111-1111-4111-8111-111111111111"
RESOURCE_ID = (
    f"/subscriptions/{SUBSCRIPTION_ID}/resourceGroups/application/"
    "providers/Microsoft.Storage/storageAccounts/insecurestorage"
)
POLICY_ID = (
    f"/subscriptions/{SUBSCRIPTION_ID}/providers/Microsoft.Authorization/"
    "policyDefinitions/require-secure-transfer"
)
ASSIGNMENT_ID = (
    f"/subscriptions/{SUBSCRIPTION_ID}/providers/Microsoft.Authorization/"
    "policyAssignments/security-baseline"
)
NOW = datetime(2026, 9, 11, 12, 0, tzinfo=UTC)
EVALUATED_AT = datetime(2026, 9, 11, 11, 30, tzinfo=UTC)
TOKEN_TIME = 1_789_000_000.0


def policy_state(compliance_state: str = "NonCompliant") -> SimpleNamespace:
    return SimpleNamespace(
        compliance_state=compliance_state,
        resource_id=RESOURCE_ID,
        policy_definition_id=POLICY_ID,
        policy_definition_name="require-secure-transfer",
        policy_assignment_id=ASSIGNMENT_ID,
        policy_assignment_scope=f"/subscriptions/{SUBSCRIPTION_ID}",
        policy_definition_action="deny",
        policy_definition_category="Storage",
        subscription_id=SUBSCRIPTION_ID,
        resource_type="Microsoft.Storage/storageAccounts",
        resource_location="eastus",
        resource_group="application",
        timestamp=EVALUATED_AT,
    )


def build_scanner(states: list[SimpleNamespace]) -> tuple[AzurePolicyScanner, MagicMock]:
    credential = MagicMock()
    credential.get_token.return_value = AccessToken("mock-token", int(TOKEN_TIME + 3600))
    policy = MagicMock()
    policy.policy_states.list_query_results_for_subscription.return_value = states
    scanner = AzurePolicyScanner(
        subscription_id=SUBSCRIPTION_ID,
        credential_factory=MagicMock(return_value=credential),
        policy_client_factory=MagicMock(return_value=policy),
        token_clock=MagicMock(return_value=TOKEN_TIME),
        scan_clock=MagicMock(return_value=NOW),
    )
    return scanner, policy


def test_non_compliant_resource_generates_normalized_finding() -> None:
    scanner, policy = build_scanner([policy_state()])

    findings = scanner.scan()

    assert len(findings) == 1
    finding = findings[0]
    assert finding.rule_id == NON_COMPLIANT_POLICY_RULE_ID
    assert finding.severity is Severity.HIGH
    assert finding.resource.provider is CloudProvider.AZURE
    assert finding.resource.resource_id == RESOURCE_ID
    assert finding.resource.account_id == SUBSCRIPTION_ID
    assert finding.resource.name == "insecurestorage"
    assert finding.scope == f"/subscriptions/{SUBSCRIPTION_ID}"
    assert finding.evidence["policy_id"] == POLICY_ID
    assert finding.evidence["subscription"] == SUBSCRIPTION_ID
    assert finding.evidence["compliance_state"] == "NonCompliant"
    assert finding.evidence["policy_evaluated_at"] == EVALUATED_AT.isoformat()
    assert SUBSCRIPTION_ID in finding.description
    assert finding.remediation_available is False
    assert finding.detected_at == NOW
    call = policy.policy_states.list_query_results_for_subscription.call_args
    assert call.kwargs["policy_states_resource"] == "latest"
    assert call.kwargs["subscription_id"] == SUBSCRIPTION_ID
    assert call.kwargs["query_options"].filter == "ComplianceState eq 'NonCompliant'"


@pytest.mark.parametrize("state", ["Compliant", "Exempt", "Unknown"])
def test_compliant_or_non_violation_states_produce_no_findings(state: str) -> None:
    scanner, _ = build_scanner([policy_state(state)])

    assert scanner.scan() == []


def test_modify_policy_marks_remediation_available() -> None:
    state = policy_state()
    state.policy_definition_action = "modify"
    scanner, _ = build_scanner([state])

    assert scanner.scan()[0].remediation_available is True


def test_duplicate_policy_states_are_collapsed() -> None:
    state = policy_state()
    scanner, _ = build_scanner([state, state])

    assert len(scanner.scan()) == 1


def test_finding_round_trips_through_json() -> None:
    scanner, _ = build_scanner([policy_state()])

    finding = scanner.scan()[0]

    assert Finding.model_validate_json(finding.model_dump_json()) == finding


def test_invalid_non_compliant_response_is_rejected() -> None:
    state = policy_state()
    state.resource_id = None
    scanner, _ = build_scanner([state])

    with pytest.raises(AzureScanError, match="invalid policy state resource_id"):
        scanner.scan()


def test_policy_state_from_another_subscription_is_rejected() -> None:
    state = policy_state()
    state.subscription_id = "22222222-2222-4222-8222-222222222222"
    scanner, _ = build_scanner([state])

    with pytest.raises(AzureScanError, match="unexpected subscription"):
        scanner.scan()


def test_policy_api_error_is_sanitized() -> None:
    scanner, policy = build_scanner([])
    response = MagicMock(status_code=403)
    error = HttpResponseError(message="sensitive Azure details", response=response)
    error.error = SimpleNamespace(code="AuthorizationFailed")
    policy.policy_states.list_query_results_for_subscription.side_effect = error

    with pytest.raises(AzureScanError, match="AuthorizationFailed") as raised:
        scanner.scan()

    assert "sensitive Azure details" not in str(raised.value)


def test_scanner_invokes_only_policy_query_operation() -> None:
    scanner, policy = build_scanner([policy_state()])

    scanner.scan()

    method_names = {method_call[0] for method_call in policy.method_calls}
    assert method_names == {"policy_states.list_query_results_for_subscription"}
    assert not any(name.endswith((".create", ".delete", ".update")) for name in method_names)
