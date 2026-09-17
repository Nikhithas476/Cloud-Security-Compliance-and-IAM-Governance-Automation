"""Read-only Azure role-based access control security scanner."""

from __future__ import annotations

from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any, NoReturn
from uuid import UUID

from azure.core.credentials import TokenCredential
from azure.core.exceptions import AzureError, HttpResponseError
from azure.identity import DefaultAzureCredential
from azure.mgmt.authorization import AuthorizationManagementClient
from pydantic import BaseModel, ConfigDict, Field, field_validator

from cloud_security_governance.azure.scanner import AzureScanner
from cloud_security_governance.exceptions import AzureConfigurationError, AzureScanError
from cloud_security_governance.models import CloudProvider, Finding, Resource, Severity

OWNER_ROLE_ID = UUID("8e3af657-a8ff-443c-a75c-2fe8c4bcb635")
CONTRIBUTOR_ROLE_ID = UUID("b24988ac-6180-42a0-ab88-20f7382dd24c")

OWNER_ASSIGNMENT_RULE_ID = "azure.rbac.owner-assignment"
CONTRIBUTOR_ASSIGNMENT_RULE_ID = "azure.rbac.contributor-assignment"
SUBSCRIPTION_PRIVILEGED_RULE_ID = "azure.rbac.subscription-privileged-assignment"
EXCESSIVE_PERMISSIONS_RULE_ID = "azure.rbac.excessive-permissions"


def _utc_now() -> datetime:
    return datetime.now(UTC)


class AzureRBACRules(BaseModel):
    """Configurable definitions of excessive and subscription-privileged access."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    excessive_actions: frozenset[str] = Field(default_factory=lambda: frozenset({"*"}))
    excessive_data_actions: frozenset[str] = Field(default_factory=lambda: frozenset({"*"}))
    subscription_privileged_role_ids: frozenset[UUID] = Field(
        default_factory=lambda: frozenset({OWNER_ROLE_ID, CONTRIBUTOR_ROLE_ID})
    )

    @field_validator("excessive_actions", "excessive_data_actions")
    @classmethod
    def validate_actions(cls, values: frozenset[str]) -> frozenset[str]:
        normalized = frozenset(value.strip().casefold() for value in values if value.strip())
        if len(normalized) != len(values):
            raise ValueError("excessive permission actions must be non-empty and unique")
        if any(len(value) > 256 for value in normalized):
            raise ValueError("excessive permission actions must be at most 256 characters")
        return normalized


@dataclass(frozen=True)
class _RoleDetails:
    name: str
    actions: frozenset[str]
    data_actions: frozenset[str]


_BUILT_IN_ROLES = {
    OWNER_ROLE_ID: _RoleDetails("Owner", frozenset({"*"}), frozenset()),
    CONTRIBUTOR_ROLE_ID: _RoleDetails("Contributor", frozenset({"*"}), frozenset()),
}


class AzureRBACScanner(AzureScanner):
    """Detect privileged Azure role assignments without modifying RBAC state."""

    def __init__(
        self,
        *,
        subscription_id: str | None = None,
        rules: AzureRBACRules | None = None,
        credential_factory: Callable[[], TokenCredential] = DefaultAzureCredential,
        authorization_client_factory: Callable[..., Any] = AuthorizationManagementClient,
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
        self.rules = rules or AzureRBACRules()
        self._scan_clock = scan_clock
        self.resources_scanned = 0
        try:
            self._authorization = authorization_client_factory(
                self._credential,
                self.subscription_id,
            )
        except (AzureError, OSError) as exc:
            raise AzureConfigurationError(
                "The Azure Authorization client could not be initialized"
            ) from exc

    def scan(self) -> list[Finding]:
        """Return one normalized finding list for all RBAC rule violations."""

        self.validate_authentication()
        detected_at = self._normalize_scan_time(self._scan_clock())
        self.resources_scanned = 0
        findings: list[Finding] = []
        role_cache: dict[UUID, _RoleDetails] = dict(_BUILT_IN_ROLES)
        try:
            assignments = self._authorization.role_assignments.list_for_subscription()
            for assignment in assignments:
                self.resources_scanned += 1
                findings.extend(self._evaluate_assignment(assignment, role_cache, detected_at))
        except HttpResponseError as exc:
            self._raise_scan_error(exc)
        except (AzureError, OSError) as exc:
            raise AzureScanError("The Azure RBAC scan could not be completed") from exc
        return findings

    def _evaluate_assignment(
        self,
        assignment: Any,
        role_cache: dict[UUID, _RoleDetails],
        detected_at: datetime,
    ) -> list[Finding]:
        assignment_id = self._required_string(assignment, "id", "role assignment")
        assignment_name = self._optional_string(assignment, "name") or assignment_id.rsplit("/", 1)[-1]
        scope = self._required_string(assignment, "scope", "role assignment")
        principal_id = self._required_string(assignment, "principal_id", "role assignment")
        principal_type = self._optional_string(assignment, "principal_type") or "Unknown"
        role_definition_id = self._required_string(
            assignment, "role_definition_id", "role assignment"
        )
        role_id = self._role_uuid(role_definition_id)
        role = role_cache.get(role_id)
        if role is None:
            role = self._get_role_details(role_definition_id)
            role_cache[role_id] = role

        resource = Resource(
            resource_id=assignment_id,
            provider=CloudProvider.AZURE,
            account_id=self.subscription_id,
            resource_type="Microsoft.Authorization/roleAssignments",
            name=assignment_name,
            metadata={"principal_type": principal_type, "role_definition_id": role_definition_id},
        )
        evidence = {
            "scope": scope,
            "principal_id": principal_id,
            "principal_type": principal_type,
            "role": role.name,
            "role_definition_id": role_definition_id,
        }
        findings: list[Finding] = []
        if role_id == OWNER_ROLE_ID:
            findings.append(
                self._finding(
                    rule_id=OWNER_ASSIGNMENT_RULE_ID,
                    title="Owner role assignment detected",
                    description=(
                        f"Principal {principal_id} has the Owner role at scope {scope}, including "
                        "full resource and access-management permissions."
                    ),
                    severity=Severity.CRITICAL,
                    resource=resource,
                    scope=scope,
                    principal=principal_id,
                    role=role.name,
                    evidence=evidence,
                    detected_at=detected_at,
                )
            )
        if role_id == CONTRIBUTOR_ROLE_ID:
            findings.append(
                self._finding(
                    rule_id=CONTRIBUTOR_ASSIGNMENT_RULE_ID,
                    title="Contributor role assignment detected",
                    description=(
                        f"Principal {principal_id} has the Contributor role at scope {scope}, "
                        "allowing broad resource-management access."
                    ),
                    severity=Severity.HIGH,
                    resource=resource,
                    scope=scope,
                    principal=principal_id,
                    role=role.name,
                    evidence=evidence,
                    detected_at=detected_at,
                )
            )
        if self._is_subscription_scope(scope) and role_id in self.rules.subscription_privileged_role_ids:
            findings.append(
                self._finding(
                    rule_id=SUBSCRIPTION_PRIVILEGED_RULE_ID,
                    title="Subscription-level privileged assignment detected",
                    description=(
                        f"Principal {principal_id} has the privileged {role.name} role across the "
                        "entire subscription."
                    ),
                    severity=Severity.CRITICAL,
                    resource=resource,
                    scope=scope,
                    principal=principal_id,
                    role=role.name,
                    evidence=evidence,
                    detected_at=detected_at,
                )
            )

        matched_actions = sorted(role.actions & self.rules.excessive_actions)
        matched_data_actions = sorted(role.data_actions & self.rules.excessive_data_actions)
        if matched_actions or matched_data_actions:
            findings.append(
                self._finding(
                    rule_id=EXCESSIVE_PERMISSIONS_RULE_ID,
                    title="Role assignment grants excessive permissions",
                    description=(
                        f"Principal {principal_id} has role {role.name} at scope {scope}, matching "
                        "configured excessive-permission rules."
                    ),
                    severity=Severity.HIGH,
                    resource=resource,
                    scope=scope,
                    principal=principal_id,
                    role=role.name,
                    evidence={
                        **evidence,
                        "matched_actions": matched_actions,
                        "matched_data_actions": matched_data_actions,
                    },
                    detected_at=detected_at,
                )
            )
        return findings

    def _get_role_details(self, role_definition_id: str) -> _RoleDetails:
        role_definition = self._authorization.role_definitions.get_by_id(role_definition_id)
        name = self._required_string(role_definition, "role_name", "role definition")
        permissions = self._attribute(role_definition, "permissions")
        if not isinstance(permissions, Iterable) or isinstance(permissions, str | bytes):
            raise AzureScanError("Azure returned invalid role-definition permissions")
        actions: set[str] = set()
        data_actions: set[str] = set()
        for permission in permissions:
            actions.update(self._permission_values(permission, "actions"))
            data_actions.update(self._permission_values(permission, "data_actions"))
        return _RoleDetails(name, frozenset(actions), frozenset(data_actions))

    @classmethod
    def _permission_values(cls, permission: Any, attribute: str) -> set[str]:
        values = cls._attribute(permission, attribute)
        if values is None:
            return set()
        if not isinstance(values, Iterable) or isinstance(values, str | bytes):
            raise AzureScanError(f"Azure returned invalid role permission {attribute}")
        normalized: set[str] = set()
        for value in values:
            if not isinstance(value, str) or not value.strip():
                raise AzureScanError(f"Azure returned invalid role permission {attribute}")
            normalized.add(value.strip().casefold())
        return normalized

    def _finding(
        self,
        *,
        rule_id: str,
        title: str,
        description: str,
        severity: Severity,
        resource: Resource,
        scope: str,
        principal: str,
        role: str,
        evidence: dict[str, Any],
        detected_at: datetime,
    ) -> Finding:
        return Finding(
            rule_id=rule_id,
            resource=resource,
            title=title,
            description=description,
            severity=severity,
            scope=scope,
            principal=principal,
            role=role,
            remediation_available=True,
            evidence=evidence,
            detected_at=detected_at,
        )

    def _is_subscription_scope(self, scope: str) -> bool:
        expected = f"/subscriptions/{self.subscription_id}"
        return scope.rstrip("/").casefold() == expected.casefold()

    @staticmethod
    def _role_uuid(role_definition_id: str) -> UUID:
        try:
            return UUID(role_definition_id.rstrip("/").rsplit("/", 1)[-1])
        except ValueError as exc:
            raise AzureScanError("Azure returned an invalid role definition ID") from exc

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
        return value.get(attribute) if isinstance(value, Mapping) else getattr(value, attribute, None)

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
        raise AzureScanError(f"The Azure RBAC scan could not be completed ({safe_code})") from error
