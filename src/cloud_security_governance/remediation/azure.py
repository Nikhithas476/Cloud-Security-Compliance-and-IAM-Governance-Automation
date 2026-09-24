"""Controlled and verified Azure RBAC remediation actions."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from azure.core.exceptions import AzureError, ResourceNotFoundError

from cloud_security_governance.exceptions import RemediationExecutionError
from cloud_security_governance.models import CloudProvider, Finding
from cloud_security_governance.remediation.core import JsonObject, RemediationExecutor

REMOVE_RBAC_ASSIGNMENT = "azure.rbac.remove-assignment"


class RemoveRBACAssignmentExecutor(RemediationExecutor):
    provider = CloudProvider.AZURE
    action = REMOVE_RBAC_ASSIGNMENT

    def __init__(self, authorization_client: Any) -> None:
        self._authorization = authorization_client

    def review(self, finding: Finding, parameters: JsonObject) -> JsonObject:
        assignment_id = self._assignment_id(finding, parameters)
        try:
            assignment = self._authorization.role_assignments.get_by_id(assignment_id)
        except (AzureError, OSError) as exc:
            raise RemediationExecutionError(
                "Azure could not read the selected RBAC assignment"
            ) from exc
        return {
            "role_assignment_id": assignment_id,
            "scope": self._attribute(assignment, "scope"),
            "principal_id": self._attribute(assignment, "principal_id"),
            "role_definition_id": self._attribute(assignment, "role_definition_id"),
            "exists": True,
        }

    def execute(self, finding: Finding, parameters: JsonObject) -> JsonObject:
        assignment_id = self._assignment_id(finding, parameters)
        try:
            self._authorization.role_assignments.delete_by_id(assignment_id)
        except (AzureError, OSError) as exc:
            raise RemediationExecutionError(
                "Azure could not remove the selected RBAC assignment"
            ) from exc
        return {"role_assignment_id": assignment_id, "exists": False}

    def verify(self, finding: Finding, parameters: JsonObject) -> tuple[bool, JsonObject]:
        assignment_id = self._assignment_id(finding, parameters)
        try:
            self._authorization.role_assignments.get_by_id(assignment_id)
        except ResourceNotFoundError:
            state = {"role_assignment_id": assignment_id, "exists": False}
            return True, state
        except (AzureError, OSError) as exc:
            raise RemediationExecutionError("Azure could not verify the RBAC assignment") from exc
        return False, {"role_assignment_id": assignment_id, "exists": True}

    @staticmethod
    def _assignment_id(finding: Finding, parameters: JsonObject) -> str:
        value = parameters.get("role_assignment_id")
        if not isinstance(value, str) or not value.strip():
            raise RemediationExecutionError("A non-empty role_assignment_id is required")
        value = value.strip()
        if value.casefold() != finding.resource.resource_id.casefold():
            raise RemediationExecutionError("The assignment does not match the approved finding")
        return value

    @staticmethod
    def _attribute(value: Any, name: str) -> Any:
        return value.get(name) if isinstance(value, Mapping) else getattr(value, name, None)
