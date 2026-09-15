"""Mocked tests for read-only Azure Storage encryption scanning."""

from __future__ import annotations

from datetime import UTC, datetime
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest
from azure.core.credentials import AccessToken
from azure.core.exceptions import HttpResponseError

from cloud_security_governance.azure import (
    AzureStorageEncryptionRules,
    AzureStorageEncryptionScanner,
)
from cloud_security_governance.azure.storage_scanner import (
    CUSTOMER_MANAGED_KEY_RULE_ID,
    INFRASTRUCTURE_ENCRYPTION_RULE_ID,
    SERVICE_ENCRYPTION_RULE_ID,
)
from cloud_security_governance.exceptions import AzureScanError
from cloud_security_governance.models import CloudProvider, Finding, Severity

SUBSCRIPTION_ID = "11111111-1111-4111-8111-111111111111"
RESOURCE_ID = (
    f"/subscriptions/{SUBSCRIPTION_ID}/resourceGroups/application/"
    "providers/Microsoft.Storage/storageAccounts/appstorage"
)
NOW = datetime(2026, 9, 15, 12, 0, tzinfo=UTC)
TOKEN_TIME = 1_789_000_000.0


def storage_account(
    *,
    blob: bool = True,
    file: bool = True,
    queue: bool = True,
    table: bool = True,
    infrastructure: bool = False,
    key_source: str = "Microsoft.Storage",
) -> SimpleNamespace:
    return SimpleNamespace(
        id=RESOURCE_ID,
        name="appstorage",
        type="Microsoft.Storage/storageAccounts",
        location="eastus",
        encryption=SimpleNamespace(
            services=SimpleNamespace(
                blob=SimpleNamespace(enabled=blob),
                file=SimpleNamespace(enabled=file),
                queue=SimpleNamespace(enabled=queue),
                table=SimpleNamespace(enabled=table),
            ),
            key_source=key_source,
            require_infrastructure_encryption=infrastructure,
        ),
    )


def build_scanner(
    accounts: list[SimpleNamespace],
    rules: AzureStorageEncryptionRules | dict[str, object] | None = None,
) -> tuple[AzureStorageEncryptionScanner, MagicMock]:
    credential = MagicMock()
    credential.get_token.return_value = AccessToken("mock-token", int(TOKEN_TIME + 3600))
    storage = MagicMock()
    storage.storage_accounts.list.return_value = accounts
    scanner = AzureStorageEncryptionScanner(
        subscription_id=SUBSCRIPTION_ID,
        rules=rules,
        credential_factory=MagicMock(return_value=credential),
        storage_client_factory=MagicMock(return_value=storage),
        token_clock=MagicMock(return_value=TOKEN_TIME),
        scan_clock=MagicMock(return_value=NOW),
    )
    return scanner, storage


def test_compliant_storage_account_produces_no_findings() -> None:
    scanner, storage = build_scanner([storage_account()])

    assert scanner.scan() == []
    storage.storage_accounts.list.assert_called_once_with()


def test_disabled_required_service_generates_normalized_finding() -> None:
    scanner, _ = build_scanner([storage_account(blob=False)])

    findings = scanner.scan()

    assert len(findings) == 1
    finding = findings[0]
    assert finding.rule_id == SERVICE_ENCRYPTION_RULE_ID
    assert finding.severity is Severity.HIGH
    assert finding.resource.provider is CloudProvider.AZURE
    assert finding.resource.account_id == SUBSCRIPTION_ID
    assert finding.resource.resource_id == RESOURCE_ID
    assert finding.evidence["unencrypted_services"] == ["blob"]
    assert finding.detected_at == NOW
    assert finding.remediation_available is True


def test_configured_services_control_which_encryption_is_required() -> None:
    scanner, _ = build_scanner(
        [storage_account(queue=False, table=False)],
        {"required_services": {"blob", "file", "queue", "table"}},
    )

    finding = scanner.scan()[0]

    assert finding.evidence["unencrypted_services"] == ["queue", "table"]


def test_strict_rules_detect_infrastructure_and_key_violations() -> None:
    rules = AzureStorageEncryptionRules(
        require_infrastructure_encryption=True,
        require_customer_managed_key=True,
        infrastructure_encryption_severity=Severity.HIGH,
        customer_managed_key_severity=Severity.CRITICAL,
    )
    scanner, _ = build_scanner([storage_account()], rules)

    findings = scanner.scan()

    assert {finding.rule_id for finding in findings} == {
        INFRASTRUCTURE_ENCRYPTION_RULE_ID,
        CUSTOMER_MANAGED_KEY_RULE_ID,
    }
    severity_by_rule = {finding.rule_id: finding.severity for finding in findings}
    assert severity_by_rule[INFRASTRUCTURE_ENCRYPTION_RULE_ID] is Severity.HIGH
    assert severity_by_rule[CUSTOMER_MANAGED_KEY_RULE_ID] is Severity.CRITICAL


def test_customer_managed_key_and_infrastructure_encryption_can_be_compliant() -> None:
    rules = AzureStorageEncryptionRules(
        require_infrastructure_encryption=True,
        require_customer_managed_key=True,
    )
    scanner, _ = build_scanner(
        [storage_account(infrastructure=True, key_source="Microsoft.Keyvault")], rules
    )

    assert scanner.scan() == []


def test_missing_encryption_details_are_reported_as_violations() -> None:
    account = storage_account()
    account.encryption = None
    scanner, _ = build_scanner([account])

    finding = scanner.scan()[0]

    assert finding.rule_id == SERVICE_ENCRYPTION_RULE_ID
    assert finding.evidence["unencrypted_services"] == ["blob", "file"]


def test_findings_round_trip_through_json() -> None:
    scanner, _ = build_scanner([storage_account(file=False)])

    finding = scanner.scan()[0]

    assert Finding.model_validate_json(finding.model_dump_json()) == finding


@pytest.mark.parametrize(
    "rules",
    [
        {"required_services": []},
        {"required_services": ["disk"]},
        {"unknown_requirement": True},
    ],
)
def test_invalid_rule_configuration_is_rejected(rules: dict[str, object]) -> None:
    with pytest.raises(ValueError):
        build_scanner([], rules)


def test_invalid_storage_account_response_is_rejected() -> None:
    account = storage_account()
    account.id = None
    scanner, _ = build_scanner([account])

    with pytest.raises(AzureScanError, match="invalid Storage account id"):
        scanner.scan()


def test_storage_api_error_is_sanitized() -> None:
    scanner, storage = build_scanner([])
    response = MagicMock(status_code=403)
    error = HttpResponseError(message="sensitive Azure details", response=response)
    error.error = SimpleNamespace(code="AuthorizationFailed")
    storage.storage_accounts.list.side_effect = error

    with pytest.raises(AzureScanError, match="AuthorizationFailed") as raised:
        scanner.scan()

    assert "sensitive Azure details" not in str(raised.value)


def test_scanner_invokes_only_read_only_storage_operations() -> None:
    scanner, storage = build_scanner([storage_account(blob=False)])

    scanner.scan()

    method_names = {method_call[0] for method_call in storage.method_calls}
    assert method_names == {"storage_accounts.list"}
    assert not any(name.endswith((".create", ".delete", ".update")) for name in method_names)
