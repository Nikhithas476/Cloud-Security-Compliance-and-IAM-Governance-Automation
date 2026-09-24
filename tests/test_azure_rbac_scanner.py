"""Mocked tests for read-only Azure RBAC security scanning."""

from __future__ import annotations

from datetime import UTC, datetime
from types import SimpleNamespace
from unittest.mock import MagicMock
from uuid import UUID

import pytest
from azure.core.credentials import AccessToken
from azure.core.exceptions import HttpResponseError

from cloud_security_governance.azure import AzureRBACRules, AzureRBACScanner
from cloud_security_governance.azure.rbac_scanner import (
    CONTRIBUTOR_ASSIGNMENT_RULE_ID,
    CONTRIBUTOR_ROLE_ID,
    EXCESSIVE_PERMISSIONS_RULE_ID,
    OWNER_ASSIGNMENT_RULE_ID,
    OWNER_ROLE_ID,
    SUBSCRIPTION_PRIVILEGED_RULE_ID,
)
from cloud_security_governance.exceptions import AzureConfigurationError, AzureScanError
from cloud_security_governance.models import Finding, Severity

SUBSCRIPTION_ID = "11111111-1111-4111-8111-111111111111"
PRINCIPAL_ID = "22222222-2222-4222-8222-222222222222"
CUSTOM_ROLE_ID = UUID("33333333-3333-4333-8333-333333333333")
NOW = datetime(2026, 9, 10, 12, 0, tzinfo=UTC)
TOKEN_TIME = 1_789_000_000.0


@pytest.fixture(autouse=True)
def clear_azure_environment(monkeypatch) -> None:
    monkeypatch.delenv("AZURE_SUBSCRIPTION_ID", raising=False)


def role_definition_path(role_id: UUID) -> str:
    return f"/subscriptions/{SUBSCRIPTION_ID}/providers/Microsoft.Authorization/roleDefinitions/{role_id}"


def assignment(
    role_id: UUID,
    *,
    scope: str | None = None,
    name: str = "44444444-4444-4444-8444-444444444444",
) -> SimpleNamespace:
    resolved_scope = scope or f"/subscriptions/{SUBSCRIPTION_ID}"
    return SimpleNamespace(
        id=(f"{resolved_scope}/providers/Microsoft.Authorization/roleAssignments/{name}"),
        name=name,
        scope=resolved_scope,
        principal_id=PRINCIPAL_ID,
        principal_type="ServicePrincipal",
        role_definition_id=role_definition_path(role_id),
    )


def build_scanner(
    assignments: list[SimpleNamespace],
    *,
    rules: AzureRBACRules | None = None,
) -> tuple[AzureRBACScanner, MagicMock, MagicMock]:
    credential = MagicMock()
    credential.get_token.return_value = AccessToken("mock-token", int(TOKEN_TIME + 3600))
    authorization = MagicMock()
    authorization.role_assignments.list_for_subscription.return_value = assignments
    client_factory = MagicMock(return_value=authorization)
    scanner = AzureRBACScanner(
        subscription_id=SUBSCRIPTION_ID,
        rules=rules,
        credential_factory=MagicMock(return_value=credential),
        authorization_client_factory=client_factory,
        token_clock=MagicMock(return_value=TOKEN_TIME),
        scan_clock=MagicMock(return_value=NOW),
    )
    client_factory.assert_called_once_with(credential, SUBSCRIPTION_ID)
    return scanner, credential, authorization


def test_owner_assignment_generates_normalized_findings() -> None:
    scanner, credential, authorization = build_scanner([assignment(OWNER_ROLE_ID)])

    findings = scanner.scan()

    assert {finding.rule_id for finding in findings} == {
        OWNER_ASSIGNMENT_RULE_ID,
        SUBSCRIPTION_PRIVILEGED_RULE_ID,
        EXCESSIVE_PERMISSIONS_RULE_ID,
    }
    owner = next(finding for finding in findings if finding.rule_id == OWNER_ASSIGNMENT_RULE_ID)
    assert owner.severity is Severity.CRITICAL
    assert owner.scope == f"/subscriptions/{SUBSCRIPTION_ID}"
    assert owner.principal == PRINCIPAL_ID
    assert owner.role == "Owner"
    assert owner.remediation_available is True
    assert owner.detected_at == NOW
    assert owner.resource.account_id == SUBSCRIPTION_ID
    assert owner.evidence["principal_type"] == "ServicePrincipal"
    credential.get_token.assert_called_once()
    authorization.role_definitions.get_by_id.assert_not_called()


def test_contributor_assignment_at_resource_group_is_not_subscription_level() -> None:
    scope = f"/subscriptions/{SUBSCRIPTION_ID}/resourceGroups/application"
    scanner, _, _ = build_scanner([assignment(CONTRIBUTOR_ROLE_ID, scope=scope)])

    findings = scanner.scan()

    assert {finding.rule_id for finding in findings} == {
        CONTRIBUTOR_ASSIGNMENT_RULE_ID,
        EXCESSIVE_PERMISSIONS_RULE_ID,
    }
    contributor = next(
        finding for finding in findings if finding.rule_id == CONTRIBUTOR_ASSIGNMENT_RULE_ID
    )
    assert contributor.severity is Severity.HIGH
    assert contributor.scope == scope
    assert contributor.role == "Contributor"


def test_configured_custom_role_is_privileged_at_subscription_scope() -> None:
    rules = AzureRBACRules(
        excessive_actions=frozenset(),
        excessive_data_actions=frozenset(),
        subscription_privileged_role_ids=frozenset({CUSTOM_ROLE_ID}),
    )
    scanner, _, authorization = build_scanner([assignment(CUSTOM_ROLE_ID)], rules=rules)
    authorization.role_definitions.get_by_id.return_value = SimpleNamespace(
        role_name="Security Operator",
        permissions=[SimpleNamespace(actions=["Microsoft.Security/alerts/read"], data_actions=[])],
    )

    findings = scanner.scan()

    assert [finding.rule_id for finding in findings] == [SUBSCRIPTION_PRIVILEGED_RULE_ID]
    assert findings[0].role == "Security Operator"


def test_custom_role_with_wildcard_action_is_excessive() -> None:
    scope = f"/subscriptions/{SUBSCRIPTION_ID}/resourceGroups/application"
    scanner, _, authorization = build_scanner([assignment(CUSTOM_ROLE_ID, scope=scope)])
    authorization.role_definitions.get_by_id.return_value = SimpleNamespace(
        role_name="Custom Administrator",
        permissions=[SimpleNamespace(actions=["*"], data_actions=[])],
    )

    findings = scanner.scan()

    assert [finding.rule_id for finding in findings] == [EXCESSIVE_PERMISSIONS_RULE_ID]
    assert findings[0].evidence["matched_actions"] == ["*"]
    assert findings[0].evidence["matched_data_actions"] == []


def test_custom_role_with_wildcard_data_action_is_excessive() -> None:
    scanner, _, authorization = build_scanner(
        [
            assignment(
                CUSTOM_ROLE_ID,
                scope=f"/subscriptions/{SUBSCRIPTION_ID}/resourceGroups/data",
            )
        ]
    )
    authorization.role_definitions.get_by_id.return_value = SimpleNamespace(
        role_name="Data Administrator",
        permissions=[SimpleNamespace(actions=["Microsoft.Storage/*/read"], data_actions=["*"])],
    )

    findings = scanner.scan()

    assert [finding.rule_id for finding in findings] == [EXCESSIVE_PERMISSIONS_RULE_ID]
    assert findings[0].evidence["matched_data_actions"] == ["*"]


def test_custom_excessive_permission_rules_are_applied_case_insensitively() -> None:
    rules = AzureRBACRules(
        excessive_actions={"Microsoft.Authorization/roleAssignments/write"},
        excessive_data_actions=frozenset(),
        subscription_privileged_role_ids=frozenset(),
    )
    scanner, _, authorization = build_scanner(
        [
            assignment(
                CUSTOM_ROLE_ID,
                scope=f"/subscriptions/{SUBSCRIPTION_ID}/resourceGroups/security",
            )
        ],
        rules=rules,
    )
    authorization.role_definitions.get_by_id.return_value = SimpleNamespace(
        role_name="Role Assignment Writer",
        permissions=[
            SimpleNamespace(
                actions=["MICROSOFT.AUTHORIZATION/ROLEASSIGNMENTS/WRITE"],
                data_actions=[],
            )
        ],
    )

    findings = scanner.scan()

    assert [finding.rule_id for finding in findings] == [EXCESSIVE_PERMISSIONS_RULE_ID]


def test_non_privileged_narrow_role_produces_no_findings() -> None:
    rules = AzureRBACRules(subscription_privileged_role_ids=frozenset())
    scanner, _, authorization = build_scanner([assignment(CUSTOM_ROLE_ID)], rules=rules)
    authorization.role_definitions.get_by_id.return_value = SimpleNamespace(
        role_name="Reader",
        permissions=[SimpleNamespace(actions=["*/read"], data_actions=[])],
    )

    findings = scanner.scan()

    assert findings == []


def test_custom_role_definition_is_cached_for_multiple_assignments() -> None:
    scope = f"/subscriptions/{SUBSCRIPTION_ID}/resourceGroups/one"
    second_scope = f"/subscriptions/{SUBSCRIPTION_ID}/resourceGroups/two"
    scanner, _, authorization = build_scanner(
        [
            assignment(CUSTOM_ROLE_ID, scope=scope),
            assignment(
                CUSTOM_ROLE_ID,
                scope=second_scope,
                name="55555555-5555-4555-8555-555555555555",
            ),
        ]
    )
    authorization.role_definitions.get_by_id.return_value = SimpleNamespace(
        role_name="Custom Administrator",
        permissions=[SimpleNamespace(actions=["*"], data_actions=[])],
    )

    findings = scanner.scan()

    assert len(findings) == 2
    authorization.role_definitions.get_by_id.assert_called_once_with(
        role_definition_path(CUSTOM_ROLE_ID)
    )


def test_findings_round_trip_through_json() -> None:
    scanner, _, _ = build_scanner([assignment(OWNER_ROLE_ID)])

    findings = scanner.scan()
    restored = [Finding.model_validate_json(finding.model_dump_json()) for finding in findings]

    assert restored == findings


@pytest.mark.parametrize(
    "rules",
    [
        {"excessive_actions": {"", "*"}},
        {"excessive_actions": {"x" * 257}},
        {"unknown_option": True},
    ],
)
def test_invalid_rule_configuration_is_rejected(rules: dict[str, object]) -> None:
    with pytest.raises(ValueError):
        AzureRBACRules.model_validate(rules)


def test_invalid_role_assignment_response_is_rejected() -> None:
    invalid_assignment = assignment(OWNER_ROLE_ID)
    invalid_assignment.principal_id = None
    scanner, _, _ = build_scanner([invalid_assignment])

    with pytest.raises(AzureScanError, match="invalid role assignment principal_id"):
        scanner.scan()


def test_invalid_role_definition_id_is_rejected() -> None:
    invalid_assignment = assignment(CUSTOM_ROLE_ID)
    invalid_assignment.role_definition_id = "/invalid/not-a-uuid"
    scanner, _, _ = build_scanner([invalid_assignment])

    with pytest.raises(AzureScanError, match="invalid role definition ID"):
        scanner.scan()


def test_authorization_api_error_is_sanitized() -> None:
    scanner, _, authorization = build_scanner([])
    response = MagicMock()
    response.status_code = 403
    error = HttpResponseError(message="sensitive Azure response details", response=response)
    error.error = SimpleNamespace(code="AuthorizationFailed")
    authorization.role_assignments.list_for_subscription.side_effect = error

    with pytest.raises(AzureScanError, match="AuthorizationFailed") as raised:
        scanner.scan()

    assert "sensitive Azure response details" not in str(raised.value)


def test_naive_scan_timestamp_is_rejected() -> None:
    credential = MagicMock()
    credential.get_token.return_value = AccessToken("mock-token", int(TOKEN_TIME + 3600))
    authorization = MagicMock()
    scanner = AzureRBACScanner(
        subscription_id=SUBSCRIPTION_ID,
        credential_factory=MagicMock(return_value=credential),
        authorization_client_factory=MagicMock(return_value=authorization),
        token_clock=MagicMock(return_value=TOKEN_TIME),
        scan_clock=MagicMock(return_value=datetime(2026, 9, 10, 12, 0)),  # noqa: DTZ001
    )

    with pytest.raises(AzureConfigurationError, match="timezone information"):
        scanner.scan()


def test_scanner_invokes_only_read_only_authorization_operations() -> None:
    scanner, _, authorization = build_scanner([assignment(OWNER_ROLE_ID)])

    scanner.scan()

    method_names = {method_call[0] for method_call in authorization.method_calls}
    assert method_names <= {"role_assignments.list_for_subscription"}
    assert not any(name.endswith((".create", ".delete", ".update")) for name in method_names)
