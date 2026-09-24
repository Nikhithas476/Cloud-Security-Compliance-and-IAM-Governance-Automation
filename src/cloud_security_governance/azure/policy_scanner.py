"""Read-only Azure Policy compliance scanner."""

from __future__ import annotations

from collections.abc import Callable, Mapping
from datetime import UTC, datetime
from typing import Any, NoReturn

from azure.core.credentials import TokenCredential
from azure.core.exceptions import AzureError, HttpResponseError
from azure.identity import DefaultAzureCredential
from azure.mgmt.policyinsights import PolicyInsightsClient
from azure.mgmt.policyinsights.models import QueryOptions

from cloud_security_governance.azure.scanner import AzureScanner
from cloud_security_governance.exceptions import AzureConfigurationError, AzureScanError
from cloud_security_governance.models import CloudProvider, Finding, Resource, Severity

NON_COMPLIANT_POLICY_RULE_ID = "azure.policy.non-compliant-resource"


def _utc_now() -> datetime:
    return datetime.now(UTC)


class AzurePolicyScanner(AzureScanner):
    """Query Azure Policy Insights and normalize non-compliant policy states."""

    def __init__(
        self,
        *,
        subscription_id: str | None = None,
        severity: Severity = Severity.HIGH,
        credential_factory: Callable[[], TokenCredential] = DefaultAzureCredential,
        policy_client_factory: Callable[..., Any] = PolicyInsightsClient,
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
        self.severity = severity
        self._scan_clock = scan_clock
        self.resources_scanned = 0
        try:
            self._policy = policy_client_factory(self._credential, self.subscription_id)
        except (AzureError, OSError) as exc:
            raise AzureConfigurationError(
                "The Azure Policy Insights client could not be initialized"
            ) from exc

    def scan(self) -> list[Finding]:
        """Return findings for the subscription's latest non-compliant policy states."""

        self.validate_authentication()
        detected_at = self._normalize_scan_time(self._scan_clock())
        self.resources_scanned = 0
        findings: list[Finding] = []
        seen: set[tuple[str, str, str]] = set()
        query = QueryOptions(filter="ComplianceState eq 'NonCompliant'")
        try:
            states = self._policy.policy_states.list_query_results_for_subscription(
                policy_states_resource="latest",
                subscription_id=self.subscription_id,
                query_options=query,
            )
            for state in states:
                self.resources_scanned += 1
                finding = self._to_finding(state, detected_at)
                if finding is None:
                    continue
                key = (
                    finding.evidence["policy_id"],
                    finding.resource.resource_id,
                    finding.evidence.get("policy_assignment_id", ""),
                )
                if key not in seen:
                    seen.add(key)
                    findings.append(finding)
        except HttpResponseError as exc:
            self._raise_scan_error(exc)
        except AzureScanError:
            raise
        except (AzureError, OSError) as exc:
            raise AzureScanError("The Azure Policy compliance scan could not be completed") from exc
        return findings

    def _to_finding(self, state: Any, detected_at: datetime) -> Finding | None:
        compliance_state = self._required_string(state, "compliance_state", "policy state")
        if compliance_state.casefold() != "noncompliant":
            return None

        resource_id = self._required_string(state, "resource_id", "policy state")
        policy_id = self._required_string(state, "policy_definition_id", "policy state")
        policy_name = (
            self._optional_string(state, "policy_definition_name") or policy_id.rsplit("/", 1)[-1]
        )
        resource_type = (
            self._optional_string(state, "resource_type") or "Microsoft.Resources/resource"
        )
        resource_name = resource_id.rstrip("/").rsplit("/", 1)[-1]
        location = self._optional_string(state, "resource_location")
        assignment_id = self._optional_string(state, "policy_assignment_id")
        assignment_scope = self._optional_string(state, "policy_assignment_scope")
        action = self._optional_string(state, "policy_definition_action")
        state_subscription = self._optional_string(state, "subscription_id") or self.subscription_id
        if state_subscription.casefold() != self.subscription_id.casefold():
            raise AzureScanError("Azure returned a policy state for an unexpected subscription")

        evidence: dict[str, Any] = {
            "policy_id": policy_id,
            "subscription": self.subscription_id,
            "compliance_state": compliance_state,
        }
        for key, value in {
            "policy_assignment_id": assignment_id,
            "policy_assignment_scope": assignment_scope,
            "policy_definition_action": action,
            "policy_definition_category": self._optional_string(
                state, "policy_definition_category"
            ),
        }.items():
            if value is not None:
                evidence[key] = value
        evaluated_at = self._attribute(state, "timestamp")
        if isinstance(evaluated_at, datetime):
            if evaluated_at.tzinfo is None or evaluated_at.utcoffset() is None:
                raise AzureScanError(
                    "Azure returned a policy timestamp without timezone information"
                )
            evidence["policy_evaluated_at"] = evaluated_at.astimezone(UTC).isoformat()

        metadata = {"policy_definition_id": policy_id}
        resource_group = self._optional_string(state, "resource_group")
        if resource_group is not None:
            metadata["resource_group"] = resource_group
        resource = Resource(
            resource_id=resource_id,
            provider=CloudProvider.AZURE,
            account_id=self.subscription_id,
            resource_type=resource_type,
            name=resource_name,
            region=location,
            metadata=metadata,
        )
        return Finding(
            rule_id=NON_COMPLIANT_POLICY_RULE_ID,
            resource=resource,
            title="Azure Policy violation detected",
            description=(
                f"Resource {resource_id} is non-compliant with Azure Policy {policy_name} "
                f"in subscription {self.subscription_id}."
            ),
            severity=self.severity,
            scope=assignment_scope or resource_id,
            remediation_available=(action or "").casefold() in {"deployifnotexists", "modify"},
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
            f"The Azure Policy compliance scan could not be completed ({safe_code})"
        ) from error
