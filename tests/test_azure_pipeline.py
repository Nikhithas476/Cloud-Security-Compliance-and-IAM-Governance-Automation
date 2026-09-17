"""Tests for the complete normalized Azure scanning pipeline."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from types import SimpleNamespace
from unittest.mock import MagicMock
from uuid import UUID

from azure.core.credentials import AccessToken

from cloud_security_governance.azure import AzureScanner
from cloud_security_governance.azure.defender_scanner import DEFENDER_RECOMMENDATION_RULE_PREFIX
from cloud_security_governance.azure.policy_scanner import NON_COMPLIANT_POLICY_RULE_ID
from cloud_security_governance.azure.rbac_scanner import (
    EXCESSIVE_PERMISSIONS_RULE_ID,
    OWNER_ASSIGNMENT_RULE_ID,
    OWNER_ROLE_ID,
    SUBSCRIPTION_PRIVILEGED_RULE_ID,
)
from cloud_security_governance.azure.storage_scanner import SERVICE_ENCRYPTION_RULE_ID
from cloud_security_governance.models import CloudProvider, ScanResult

SUBSCRIPTION_ID = "11111111-1111-4111-8111-111111111111"
TENANT_ID = "22222222-2222-4222-8222-222222222222"
PRINCIPAL_ID = "33333333-3333-4333-8333-333333333333"
ASSESSMENT_NAME = "44444444-4444-4444-8444-444444444444"
NOW = datetime(2026, 9, 17, 12, 0, tzinfo=UTC)
TOKEN_TIME = 1_789_000_000.0
STORAGE_ID = (
    f"/subscriptions/{SUBSCRIPTION_ID}/resourceGroups/application/"
    "providers/Microsoft.Storage/storageAccounts/appstorage"
)
VM_ID = (
    f"/subscriptions/{SUBSCRIPTION_ID}/resourceGroups/application/"
    "providers/Microsoft.Compute/virtualMachines/web01"
)


def build_complete_pipeline() -> tuple[AzureScanner, MagicMock, dict[str, MagicMock]]:
    credential = MagicMock()
    credential.get_token.return_value = AccessToken("mock-token", int(TOKEN_TIME + 3600))

    authorization = MagicMock()
    role_path = (
        f"/subscriptions/{SUBSCRIPTION_ID}/providers/Microsoft.Authorization/"
        f"roleDefinitions/{OWNER_ROLE_ID}"
    )
    authorization.role_assignments.list_for_subscription.return_value = [
        SimpleNamespace(
            id=(
                f"/subscriptions/{SUBSCRIPTION_ID}/providers/Microsoft.Authorization/"
                "roleAssignments/55555555-5555-4555-8555-555555555555"
            ),
            name="55555555-5555-4555-8555-555555555555",
            scope=f"/subscriptions/{SUBSCRIPTION_ID}",
            principal_id=PRINCIPAL_ID,
            principal_type="ServicePrincipal",
            role_definition_id=role_path,
        )
    ]

    policy = MagicMock()
    policy.policy_states.list_query_results_for_subscription.return_value = [
        SimpleNamespace(
            compliance_state="NonCompliant",
            resource_id=VM_ID,
            policy_definition_id=(
                f"/subscriptions/{SUBSCRIPTION_ID}/providers/Microsoft.Authorization/"
                "policyDefinitions/require-monitoring"
            ),
            policy_definition_name="require-monitoring",
            policy_assignment_id=None,
            policy_assignment_scope=f"/subscriptions/{SUBSCRIPTION_ID}",
            policy_definition_action="audit",
            policy_definition_category="Monitoring",
            subscription_id=SUBSCRIPTION_ID,
            resource_type="Microsoft.Compute/virtualMachines",
            resource_location="eastus",
            resource_group="application",
            timestamp=NOW,
        )
    ]

    storage = MagicMock()
    storage.storage_accounts.list.return_value = [
        SimpleNamespace(
            id=STORAGE_ID,
            name="appstorage",
            type="Microsoft.Storage/storageAccounts",
            location="eastus",
            encryption=SimpleNamespace(
                services=SimpleNamespace(
                    blob=SimpleNamespace(enabled=False),
                    file=SimpleNamespace(enabled=True),
                ),
                key_source="Microsoft.Storage",
                require_infrastructure_encryption=False,
            ),
        )
    ]

    security = MagicMock()
    assessment_id = f"{VM_ID}/providers/Microsoft.Security/assessments/{ASSESSMENT_NAME}"
    security.assessments.list.return_value = [
        SimpleNamespace(
            id=assessment_id,
            name=ASSESSMENT_NAME,
            display_name=None,
            resource_details=SimpleNamespace(id=VM_ID),
            metadata=SimpleNamespace(
                display_name="Install endpoint protection",
                description="Endpoint protection is missing.",
                remediation_description="Install endpoint protection.",
                severity="Medium",
                policy_definition_id=None,
            ),
            status=SimpleNamespace(
                code="Unhealthy",
                cause="OffByPolicy",
                description="The resource is unhealthy.",
                first_evaluation_date=NOW,
                status_change_date=NOW,
            ),
        )
    ]

    clients = {
        "authorization": authorization,
        "policy": policy,
        "storage": storage,
        "security": security,
    }
    scanner = AzureScanner(
        subscription_id=SUBSCRIPTION_ID,
        tenant_id=TENANT_ID,
        credential_factory=MagicMock(return_value=credential),
        clock=MagicMock(return_value=TOKEN_TIME),
        scan_clock=MagicMock(side_effect=[NOW, NOW + timedelta(seconds=5)]),
        authorization_client_factory=MagicMock(return_value=authorization),
        policy_client_factory=MagicMock(return_value=policy),
        storage_client_factory=MagicMock(return_value=storage),
        security_client_factory=MagicMock(return_value=security),
    )
    return scanner, credential, clients


def test_complete_pipeline_returns_one_normalized_finding_list() -> None:
    scanner, credential, clients = build_complete_pipeline()

    result = scanner.scan()

    assert isinstance(result, ScanResult)
    assert {finding.rule_id for finding in result.findings} == {
        OWNER_ASSIGNMENT_RULE_ID,
        SUBSCRIPTION_PRIVILEGED_RULE_ID,
        EXCESSIVE_PERMISSIONS_RULE_ID,
        NON_COMPLIANT_POLICY_RULE_ID,
        SERVICE_ENCRYPTION_RULE_ID,
        f"{DEFENDER_RECOMMENDATION_RULE_PREFIX}.{ASSESSMENT_NAME}",
    }
    assert all(finding.resource.provider is CloudProvider.AZURE for finding in result.findings)
    assert all(finding.resource.account_id == SUBSCRIPTION_ID for finding in result.findings)
    assert result.account.account_id == SUBSCRIPTION_ID
    assert result.account.tenant_id == UUID(TENANT_ID)
    assert result.resources_scanned == 4
    assert result.findings_count == 6
    assert result.started_at == NOW
    assert result.duration_seconds == 5.0
    assert result.errors == []
    credential.get_token.assert_called_once()
    clients["authorization"].role_definitions.get_by_id.assert_not_called()


def test_pipeline_metadata_round_trips_through_json() -> None:
    scanner, _, _ = build_complete_pipeline()

    result = scanner.scan()
    restored = ScanResult.model_validate_json(result.model_dump_json())

    assert restored == result
    assert restored.scan_id == result.scan_id
    assert restored.findings_count == len(restored.findings)


def test_pipeline_uses_only_read_only_cloud_operations() -> None:
    scanner, _, clients = build_complete_pipeline()

    scanner.scan()

    calls = {
        name: {method_call[0] for method_call in client.method_calls}
        for name, client in clients.items()
    }
    assert calls["authorization"] == {"role_assignments.list_for_subscription"}
    assert calls["policy"] == {"policy_states.list_query_results_for_subscription"}
    assert calls["storage"] == {"storage_accounts.list"}
    assert calls["security"] == {"assessments.list"}
    assert not any(
        method.endswith((".create", ".delete", ".update"))
        for methods in calls.values()
        for method in methods
    )
