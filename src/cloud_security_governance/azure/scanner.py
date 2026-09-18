"""Secure Azure authentication and scanner foundation."""

from __future__ import annotations

import os
import time
from collections.abc import Callable
from datetime import UTC, datetime
from typing import Any
from uuid import UUID

from azure.core.credentials import TokenCredential
from azure.core.exceptions import AzureError, ClientAuthenticationError
from azure.identity import CredentialUnavailableError, DefaultAzureCredential

from cloud_security_governance.base_scanner import BaseScanner
from cloud_security_governance.exceptions import (
    AzureAuthenticationError,
    AzureConfigurationError,
    AzureScanError,
)
from cloud_security_governance.models import CloudAccount, CloudProvider, ScanResult, Severity

AZURE_MANAGEMENT_SCOPE = "https://management.azure.com/.default"


def _utc_now() -> datetime:
    return datetime.now(UTC)


class AzureScanner(BaseScanner):
    """Initialize secure Azure credentials and expose authentication validation.

    ``DefaultAzureCredential`` uses the Azure SDK credential chain, including local developer
    credentials and managed/workload identities. Credential values are never accepted, stored,
    logged, or returned by this scanner.
    """

    provider = CloudProvider.AZURE

    def __init__(
        self,
        *,
        subscription_id: str | None = None,
        tenant_id: str | None = None,
        rbac_rules: Any | None = None,
        storage_encryption_rules: Any | None = None,
        policy_severity: Severity = Severity.HIGH,
        credential_factory: Callable[[], TokenCredential] = DefaultAzureCredential,
        clock: Callable[[], float] = time.time,
        scan_clock: Callable[[], datetime] = _utc_now,
        authorization_client_factory: Callable[..., Any] | None = None,
        policy_client_factory: Callable[..., Any] | None = None,
        storage_client_factory: Callable[..., Any] | None = None,
        security_client_factory: Callable[..., Any] | None = None,
    ) -> None:
        self.subscription_id = self._resolve_subscription_id(subscription_id)
        self.tenant_id = self._resolve_tenant_id(tenant_id)
        self._clock = clock
        self._scan_clock = scan_clock
        self._pipeline_rbac_rules = rbac_rules
        self._pipeline_storage_rules = storage_encryption_rules
        self._pipeline_policy_severity = policy_severity
        self._pipeline_client_factories = {
            "authorization_client_factory": authorization_client_factory,
            "policy_client_factory": policy_client_factory,
            "storage_client_factory": storage_client_factory,
            "security_client_factory": security_client_factory,
        }
        self._authentication_validated = False
        self._reuse_authentication = False
        try:
            self._credential = credential_factory()
        except (AzureError, OSError) as exc:
            raise AzureConfigurationError("Azure credentials could not be initialized") from exc

    @staticmethod
    def _resolve_subscription_id(explicit_value: str | None) -> str:
        value = explicit_value if explicit_value is not None else os.getenv("AZURE_SUBSCRIPTION_ID")
        if value is None or not value.strip():
            raise AzureConfigurationError("AZURE_SUBSCRIPTION_ID is required")
        try:
            subscription_id = UUID(value.strip())
        except ValueError as exc:
            raise AzureConfigurationError("AZURE_SUBSCRIPTION_ID must be a valid UUID") from exc
        if subscription_id.int == 0:
            raise AzureConfigurationError("AZURE_SUBSCRIPTION_ID must not be the placeholder UUID")
        return str(subscription_id)

    @staticmethod
    def _resolve_tenant_id(explicit_value: str | None) -> str | None:
        value = explicit_value if explicit_value is not None else os.getenv("AZURE_TENANT_ID")
        if value is None:
            return None
        if not value.strip():
            raise AzureConfigurationError("AZURE_TENANT_ID must not be empty")
        try:
            tenant_id = UUID(value.strip())
        except ValueError as exc:
            raise AzureConfigurationError("AZURE_TENANT_ID must be a valid UUID") from exc
        if tenant_id.int == 0:
            raise AzureConfigurationError("AZURE_TENANT_ID must not be the placeholder UUID")
        return str(tenant_id)

    def validate_authentication(self) -> bool:
        """Request and validate an Azure Resource Manager access token."""

        if self._reuse_authentication and self._authentication_validated:
            return True
        try:
            access_token = self._credential.get_token(AZURE_MANAGEMENT_SCOPE)
        except CredentialUnavailableError as exc:
            raise AzureAuthenticationError(
                "No credential in the DefaultAzureCredential chain is available"
            ) from exc
        except ClientAuthenticationError as exc:
            raise AzureAuthenticationError("Azure authentication failed") from exc
        except (AzureError, OSError) as exc:
            raise AzureAuthenticationError("Azure authentication could not be validated") from exc

        token = getattr(access_token, "token", None)
        expires_on = getattr(access_token, "expires_on", None)
        if not isinstance(token, str) or not token:
            raise AzureAuthenticationError("Azure returned an invalid access token")
        if not isinstance(expires_on, int | float) or isinstance(expires_on, bool):
            raise AzureAuthenticationError("Azure returned an invalid token expiration")
        if expires_on <= self._clock():
            raise AzureAuthenticationError("Azure returned an expired access token")
        self._authentication_validated = True
        return True

    def scan(self) -> ScanResult:
        """Run every read-only Azure scanner and return one normalized result."""

        if self.tenant_id is None:
            raise AzureConfigurationError("AZURE_TENANT_ID is required for an aggregate Azure scan")

        # Local imports avoid cycles because every specialized scanner subclasses this class.
        from cloud_security_governance.azure.defender_scanner import AzureDefenderScanner
        from cloud_security_governance.azure.policy_scanner import AzurePolicyScanner
        from cloud_security_governance.azure.rbac_scanner import AzureRBACScanner
        from cloud_security_governance.azure.storage_scanner import AzureStorageEncryptionScanner

        started_at = self._normalize_scan_time(self._scan_clock())
        self.validate_authentication()
        shared_options: dict[str, Any] = {
            "subscription_id": self.subscription_id,
            "credential_factory": lambda: self._credential,
            "token_clock": self._clock,
            "scan_clock": lambda: started_at,
        }

        component_specs = (
            (
                AzureRBACScanner,
                "authorization_client_factory",
                {"rules": self._pipeline_rbac_rules},
            ),
            (
                AzurePolicyScanner,
                "policy_client_factory",
                {"severity": self._pipeline_policy_severity},
            ),
            (
                AzureStorageEncryptionScanner,
                "storage_client_factory",
                {"rules": self._pipeline_storage_rules},
            ),
            (AzureDefenderScanner, "security_client_factory", {}),
        )
        scanners = []
        for scanner_type, factory_name, options in component_specs:
            factory = self._pipeline_client_factories[factory_name]
            if factory is not None:
                options[factory_name] = factory
            scanner = scanner_type(**shared_options, **options)
            scanner._authentication_validated = True
            scanner._reuse_authentication = True
            scanners.append(scanner)

        findings = []
        resources_scanned = 0
        for scanner in scanners:
            component_findings = scanner.scan()
            for finding in component_findings:
                if (
                    finding.resource.provider is not CloudProvider.AZURE
                    or finding.resource.account_id != self.subscription_id
                ):
                    raise AzureScanError(
                        "An Azure scanner returned a finding for a different subscription"
                    )
            findings.extend(component_findings)
            resources_scanned += scanner.resources_scanned

        completed_at = max(self._normalize_scan_time(self._scan_clock()), started_at)
        return ScanResult(
            account=CloudAccount(
                account_id=self.subscription_id,
                provider=CloudProvider.AZURE,
                display_name=f"Azure subscription {self.subscription_id}",
                tenant_id=UUID(self.tenant_id),
            ),
            started_at=started_at,
            completed_at=completed_at,
            resources_scanned=resources_scanned,
            findings=findings,
        )

    @staticmethod
    def _normalize_scan_time(value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise AzureConfigurationError("Azure scan timestamps must include timezone information")
        return value.astimezone(UTC)
