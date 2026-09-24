"""Read-only Azure Storage account encryption scanner."""

from __future__ import annotations

from collections.abc import Callable, Mapping
from datetime import UTC, datetime
from typing import Any, Literal, NoReturn

from azure.core.credentials import TokenCredential
from azure.core.exceptions import AzureError, HttpResponseError
from azure.identity import DefaultAzureCredential
from azure.mgmt.storage import StorageManagementClient
from pydantic import BaseModel, ConfigDict, Field

from cloud_security_governance.azure.scanner import AzureScanner
from cloud_security_governance.exceptions import AzureConfigurationError, AzureScanError
from cloud_security_governance.models import CloudProvider, Finding, Resource, Severity

StorageService = Literal["blob", "file", "queue", "table"]

SERVICE_ENCRYPTION_RULE_ID = "azure.storage.encryption.service-enabled"
INFRASTRUCTURE_ENCRYPTION_RULE_ID = "azure.storage.encryption.infrastructure-enabled"
CUSTOMER_MANAGED_KEY_RULE_ID = "azure.storage.encryption.customer-managed-key"


def _utc_now() -> datetime:
    return datetime.now(UTC)


class AzureStorageEncryptionRules(BaseModel):
    """Validated, configuration-driven Azure Storage encryption requirements."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    required_services: frozenset[StorageService] = Field(
        default_factory=lambda: frozenset({"blob", "file"}), min_length=1
    )
    require_infrastructure_encryption: bool = False
    require_customer_managed_key: bool = False
    service_encryption_severity: Severity = Severity.HIGH
    infrastructure_encryption_severity: Severity = Severity.MEDIUM
    customer_managed_key_severity: Severity = Severity.HIGH


class AzureStorageEncryptionScanner(AzureScanner):
    """Detect Storage accounts that violate configured encryption requirements."""

    def __init__(
        self,
        *,
        subscription_id: str | None = None,
        rules: AzureStorageEncryptionRules | Mapping[str, Any] | None = None,
        credential_factory: Callable[[], TokenCredential] = DefaultAzureCredential,
        storage_client_factory: Callable[..., Any] = StorageManagementClient,
        token_clock: Callable[[], float] | None = None,
        scan_clock: Callable[[], datetime] = _utc_now,
    ) -> None:
        base_options: dict[str, Any] = {
            "subscription_id": subscription_id,
            "credential_factory": credential_factory,
        }
        if token_clock is not None:
            base_options["clock"] = token_clock
        super().__init__(**base_options)
        self.rules = AzureStorageEncryptionRules.model_validate(rules or {})
        self._scan_clock = scan_clock
        self.resources_scanned = 0
        try:
            self._storage = storage_client_factory(self._credential, self.subscription_id)
        except (AzureError, OSError) as exc:
            raise AzureConfigurationError(
                "The Azure Storage management client could not be initialized"
            ) from exc

    def scan(self) -> list[Finding]:
        """List Storage accounts and return their encryption violations."""

        self.validate_authentication()
        detected_at = self._normalize_scan_time(self._scan_clock())
        self.resources_scanned = 0
        findings: list[Finding] = []
        try:
            for account in self._storage.storage_accounts.list():
                self.resources_scanned += 1
                findings.extend(self._evaluate_account(account, detected_at))
        except HttpResponseError as exc:
            self._raise_scan_error(exc)
        except AzureScanError:
            raise
        except (AzureError, OSError) as exc:
            raise AzureScanError(
                "The Azure Storage encryption scan could not be completed"
            ) from exc
        return findings

    def _evaluate_account(self, account: Any, detected_at: datetime) -> list[Finding]:
        resource_id = self._required_string(account, "id", "Storage account")
        name = self._required_string(account, "name", "Storage account")
        resource_type = (
            self._optional_string(account, "type") or "Microsoft.Storage/storageAccounts"
        )
        location = self._optional_string(account, "location")
        encryption = self._attribute(account, "encryption")
        services = self._attribute(encryption, "services") if encryption is not None else None
        key_source = (
            self._optional_string(encryption, "key_source") if encryption is not None else None
        )
        infrastructure_enabled = (
            self._attribute(encryption, "require_infrastructure_encryption") is True
            if encryption is not None
            else False
        )
        resource = Resource(
            resource_id=resource_id,
            provider=CloudProvider.AZURE,
            account_id=self.subscription_id,
            resource_type=resource_type,
            name=name,
            region=location,
        )
        base_evidence: dict[str, Any] = {
            "subscription": self.subscription_id,
            "key_source": key_source or "unspecified",
            "infrastructure_encryption_enabled": infrastructure_enabled,
        }
        findings: list[Finding] = []

        missing_services = sorted(
            service
            for service in self.rules.required_services
            if self._attribute(self._attribute(services, service), "enabled") is not True
        )
        if missing_services:
            findings.append(
                self._finding(
                    rule_id=SERVICE_ENCRYPTION_RULE_ID,
                    title="Required Storage service encryption is not enabled",
                    description=(
                        f"Storage account {name} does not report encryption enabled for required "
                        f"services: {', '.join(missing_services)}."
                    ),
                    severity=self.rules.service_encryption_severity,
                    resource=resource,
                    evidence={**base_evidence, "unencrypted_services": missing_services},
                    detected_at=detected_at,
                )
            )
        if self.rules.require_infrastructure_encryption and not infrastructure_enabled:
            findings.append(
                self._finding(
                    rule_id=INFRASTRUCTURE_ENCRYPTION_RULE_ID,
                    title="Infrastructure encryption is not enabled",
                    description=(
                        f"Storage account {name} does not use the required secondary layer of "
                        "infrastructure encryption."
                    ),
                    severity=self.rules.infrastructure_encryption_severity,
                    resource=resource,
                    evidence=base_evidence,
                    detected_at=detected_at,
                )
            )
        if self.rules.require_customer_managed_key and (key_source or "").casefold() != (
            "Microsoft.Keyvault".casefold()
        ):
            findings.append(
                self._finding(
                    rule_id=CUSTOMER_MANAGED_KEY_RULE_ID,
                    title="Customer-managed encryption key is not configured",
                    description=(
                        f"Storage account {name} does not use the required customer-managed "
                        "Azure Key Vault encryption key."
                    ),
                    severity=self.rules.customer_managed_key_severity,
                    resource=resource,
                    evidence=base_evidence,
                    detected_at=detected_at,
                )
            )
        return findings

    @staticmethod
    def _finding(
        *,
        rule_id: str,
        title: str,
        description: str,
        severity: Severity,
        resource: Resource,
        evidence: dict[str, Any],
        detected_at: datetime,
    ) -> Finding:
        return Finding(
            rule_id=rule_id,
            resource=resource,
            title=title,
            description=description,
            severity=severity,
            scope=resource.resource_id,
            remediation_available=True,
            evidence=evidence,
            detected_at=detected_at,
        )

    @classmethod
    def _required_string(cls, value: Any, attribute: str, context: str) -> str:
        result = cls._attribute(value, attribute)
        if not isinstance(result, str) or not result.strip():
            raise AzureScanError(f"Azure returned an invalid {context} {attribute}")
        return result.strip()

    @classmethod
    def _optional_string(cls, value: Any, attribute: str) -> str | None:
        result = cls._attribute(value, attribute)
        return result.strip() if isinstance(result, str) and result.strip() else None

    @staticmethod
    def _attribute(value: Any, attribute: str) -> Any:
        if value is None:
            return None
        return (
            value.get(attribute) if isinstance(value, Mapping) else getattr(value, attribute, None)
        )

    @staticmethod
    def _normalize_scan_time(value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise AzureConfigurationError("Azure scan timestamps must include timezone information")
        return value.astimezone(UTC)

    @staticmethod
    def _raise_scan_error(error: HttpResponseError) -> NoReturn:
        service_error = getattr(error, "error", None)
        code = getattr(service_error, "code", None)
        safe_code = str(code) if code else str(getattr(error, "status_code", "UnknownError"))
        raise AzureScanError(
            f"The Azure Storage encryption scan could not be completed ({safe_code})"
        ) from error
