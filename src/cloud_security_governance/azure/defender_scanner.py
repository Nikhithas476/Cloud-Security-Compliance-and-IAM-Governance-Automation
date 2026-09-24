"""Read-only Microsoft Defender for Cloud recommendation scanner."""

from __future__ import annotations

from collections.abc import Callable, Mapping
from datetime import UTC, datetime
from typing import Any, NoReturn

from azure.core.credentials import TokenCredential
from azure.core.exceptions import AzureError, HttpResponseError
from azure.identity import DefaultAzureCredential
from azure.mgmt.security import SecurityCenter

from cloud_security_governance.azure.scanner import AzureScanner
from cloud_security_governance.exceptions import AzureConfigurationError, AzureScanError
from cloud_security_governance.models import CloudProvider, Finding, Resource, Severity

DEFENDER_RECOMMENDATION_RULE_PREFIX = "azure.defender.recommendation"
_ASSESSMENT_MARKER = "/providers/microsoft.security/assessments/"
_SEVERITY_MAP = {
    "high": Severity.HIGH,
    "medium": Severity.MEDIUM,
    "low": Severity.LOW,
    "informational": Severity.INFORMATIONAL,
}


def _utc_now() -> datetime:
    return datetime.now(UTC)


class AzureDefenderScanner(AzureScanner):
    """Normalize unhealthy Defender for Cloud assessments into findings."""

    def __init__(
        self,
        *,
        subscription_id: str | None = None,
        credential_factory: Callable[[], TokenCredential] = DefaultAzureCredential,
        security_client_factory: Callable[..., Any] = SecurityCenter,
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
        self._scan_clock = scan_clock
        self.resources_scanned = 0
        try:
            self._security = security_client_factory(self._credential, self.subscription_id)
        except (AzureError, OSError) as exc:
            raise AzureConfigurationError(
                "The Microsoft Defender for Cloud client could not be initialized"
            ) from exc

    def scan(self) -> list[Finding]:
        """Return findings for unhealthy assessments in the configured subscription."""

        self.validate_authentication()
        detected_at = self._normalize_scan_time(self._scan_clock())
        scope = f"/subscriptions/{self.subscription_id}"
        self.resources_scanned = 0
        findings: list[Finding] = []
        try:
            for assessment in self._security.assessments.list(scope):
                self.resources_scanned += 1
                finding = self._to_finding(assessment, detected_at)
                if finding is not None:
                    findings.append(finding)
        except HttpResponseError as exc:
            self._raise_scan_error(exc)
        except AzureScanError:
            raise
        except (AzureError, OSError) as exc:
            raise AzureScanError("The Defender for Cloud scan could not be completed") from exc
        return findings

    def _to_finding(self, assessment: Any, detected_at: datetime) -> Finding | None:
        status = self._attribute(assessment, "status")
        status_code = self._optional_string(status, "code")
        if status_code is None or status_code.casefold() != "unhealthy":
            return None

        assessment_id = self._optional_string(assessment, "id")
        assessment_name = self._optional_string(assessment, "name")
        if assessment_name is None and assessment_id is not None:
            assessment_name = assessment_id.rstrip("/").rsplit("/", 1)[-1]
        if assessment_name is None:
            return None

        resource_details = self._attribute(assessment, "resource_details")
        resource_id = self._optional_string(resource_details, "id")
        if resource_id is None:
            resource_id = self._resource_id_from_assessment_id(assessment_id)
        if resource_id is None:
            return None
        expected_scope = f"/subscriptions/{self.subscription_id}/"
        if not resource_id.casefold().startswith(expected_scope.casefold()):
            raise AzureScanError(
                "Defender returned an assessment outside the configured subscription"
            )

        metadata = self._attribute(assessment, "metadata")
        title = (
            self._optional_string(assessment, "display_name")
            or self._optional_string(metadata, "display_name")
            or f"Defender recommendation {assessment_name}"
        )
        status_description = self._optional_string(status, "description")
        description = (
            self._optional_string(metadata, "description")
            or status_description
            or f"Microsoft Defender for Cloud reports resource {resource_id} as unhealthy."
        )
        defender_severity = self._optional_string(metadata, "severity")
        severity = self.map_severity(defender_severity)
        remediation = self._optional_string(metadata, "remediation_description")
        resource = Resource(
            resource_id=resource_id,
            provider=CloudProvider.AZURE,
            account_id=self.subscription_id,
            resource_type=self._resource_type(resource_id),
            name=resource_id.rstrip("/").rsplit("/", 1)[-1],
        )
        evidence: dict[str, Any] = {
            "assessment_name": assessment_name,
            "status": status_code,
            "subscription": self.subscription_id,
            "defender_severity": defender_severity or "unspecified",
        }
        for key, value in {
            "assessment_id": assessment_id,
            "status_cause": self._optional_string(status, "cause"),
            "status_description": status_description,
            "remediation_description": remediation,
            "policy_definition_id": self._optional_string(metadata, "policy_definition_id"),
        }.items():
            if value is not None:
                evidence[key] = value
        self._add_timestamp(evidence, status, "first_evaluation_date")
        self._add_timestamp(evidence, status, "status_change_date")

        return Finding(
            rule_id=f"{DEFENDER_RECOMMENDATION_RULE_PREFIX}.{assessment_name}",
            resource=resource,
            title=title,
            description=description,
            severity=severity,
            scope=resource_id,
            remediation_available=remediation is not None,
            evidence=evidence,
            detected_at=detected_at,
        )

    @staticmethod
    def map_severity(value: str | None) -> Severity:
        """Map Defender severity strings, defaulting unknown or missing data safely."""

        if value is None:
            return Severity.INFORMATIONAL
        return _SEVERITY_MAP.get(value.strip().casefold(), Severity.INFORMATIONAL)

    @staticmethod
    def _resource_id_from_assessment_id(assessment_id: str | None) -> str | None:
        if assessment_id is None:
            return None
        index = assessment_id.casefold().find(_ASSESSMENT_MARKER)
        return assessment_id[:index] if index > 0 else None

    @staticmethod
    def _resource_type(resource_id: str) -> str:
        segments = resource_id.strip("/").split("/")
        provider_indexes = [
            index for index, segment in enumerate(segments) if segment.casefold() == "providers"
        ]
        if not provider_indexes:
            return "Microsoft.Resources/resource"
        provider_parts = segments[provider_indexes[-1] + 1 :]
        if len(provider_parts) < 2:
            return "Microsoft.Resources/resource"
        return "/".join([provider_parts[0], *provider_parts[1::2]])

    @classmethod
    def _add_timestamp(cls, evidence: dict[str, Any], value: Any, attribute: str) -> None:
        timestamp = cls._attribute(value, attribute)
        if (
            isinstance(timestamp, datetime)
            and timestamp.tzinfo is not None
            and timestamp.utcoffset() is not None
        ):
            evidence[attribute] = timestamp.astimezone(UTC).isoformat()

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
            f"The Defender for Cloud scan could not be completed ({safe_code})"
        ) from error
