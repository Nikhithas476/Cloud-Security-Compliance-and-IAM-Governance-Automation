"""Narrow, verified AWS IAM remediation actions."""

from __future__ import annotations

import copy
import json
from datetime import datetime
from typing import Any
from urllib.parse import unquote

from botocore.exceptions import BotoCoreError, ClientError

from cloud_security_governance.exceptions import RemediationExecutionError
from cloud_security_governance.models import CloudProvider, Finding
from cloud_security_governance.remediation.core import JsonObject, RemediationExecutor

DISABLE_STALE_ACCESS_KEY = "aws.iam.disable-stale-access-key"
REMOVE_POLICY_PERMISSION = "aws.iam.remove-policy-permission"


def _required(parameters: JsonObject, name: str) -> str:
    value = parameters.get(name)
    if not isinstance(value, str) or not value.strip():
        raise RemediationExecutionError(f"A non-empty {name} is required")
    return value.strip()


def _safe_time(value: Any) -> str | None:
    return value.isoformat() if isinstance(value, datetime) else None


class DisableStaleAccessKeyExecutor(RemediationExecutor):
    provider = CloudProvider.AWS
    action = DISABLE_STALE_ACCESS_KEY

    def __init__(self, iam_client: Any) -> None:
        self._iam = iam_client

    def review(self, finding: Finding, parameters: JsonObject) -> JsonObject:
        user = _required(parameters, "user_name")
        key_id = _required(parameters, "access_key_id")
        key = self._find_key(user, key_id)
        return {
            "user_name": user,
            "access_key_id": key_id,
            "status": key.get("Status"),
            "created_at": _safe_time(key.get("CreateDate")),
        }

    def execute(self, finding: Finding, parameters: JsonObject) -> JsonObject:
        user = _required(parameters, "user_name")
        key_id = _required(parameters, "access_key_id")
        try:
            self._iam.update_access_key(UserName=user, AccessKeyId=key_id, Status="Inactive")
        except (BotoCoreError, ClientError, OSError) as exc:
            raise RemediationExecutionError(
                "AWS could not disable the selected access key"
            ) from exc
        return {"user_name": user, "access_key_id": key_id, "status": "Inactive"}

    def verify(self, finding: Finding, parameters: JsonObject) -> tuple[bool, JsonObject]:
        state = self.review(finding, parameters)
        return state.get("status") == "Inactive", state

    def _find_key(self, user: str, key_id: str) -> JsonObject:
        try:
            response = self._iam.list_access_keys(UserName=user)
            keys = response.get("AccessKeyMetadata", [])
        except (BotoCoreError, ClientError, OSError) as exc:
            raise RemediationExecutionError("AWS could not read the selected access key") from exc
        for key in keys:
            if key.get("AccessKeyId") == key_id:
                return key
        raise RemediationExecutionError("The selected access key does not exist")


class RemovePolicyPermissionExecutor(RemediationExecutor):
    """Remove one exact Action/Resource value by creating a new managed-policy version."""

    provider = CloudProvider.AWS
    action = REMOVE_POLICY_PERMISSION

    def __init__(self, iam_client: Any) -> None:
        self._iam = iam_client

    def review(self, finding: Finding, parameters: JsonObject) -> JsonObject:
        document, version = self._document(parameters)
        index, field, value = self._target(parameters)
        present = self._permission_present(document, index, field, value)
        if not present:
            raise RemediationExecutionError("The exact policy permission is not present")
        return {
            "policy_arn": _required(parameters, "policy_arn"),
            "version_id": version,
            "statement_index": index,
            "permission_field": field,
            "permission_value": value,
            "permission_present": True,
        }

    def execute(self, finding: Finding, parameters: JsonObject) -> JsonObject:
        document, _ = self._document(parameters)
        index, field, value = self._target(parameters)
        statements = document.get("Statement")
        if not isinstance(statements, list) or index >= len(statements):
            raise RemediationExecutionError("The selected policy statement does not exist")
        statement = statements[index]
        current = statement.get(field)
        if isinstance(current, list):
            remaining = [item for item in current if item != value]
            if len(remaining) == len(current):
                raise RemediationExecutionError("The exact policy permission is not present")
            if remaining:
                statement[field] = remaining[0] if len(remaining) == 1 else remaining
            else:
                statements.pop(index)
        elif current == value:
            statements.pop(index)
        else:
            raise RemediationExecutionError("The exact policy permission is not present")
        try:
            response = self._iam.create_policy_version(
                PolicyArn=_required(parameters, "policy_arn"),
                PolicyDocument=json.dumps(document, separators=(",", ":")),
                SetAsDefault=True,
            )
        except (BotoCoreError, ClientError, OSError) as exc:
            raise RemediationExecutionError("AWS could not update the selected IAM policy") from exc
        version_id = response.get("PolicyVersion", {}).get("VersionId")
        return {"permission_present": False, "version_id": version_id}

    def verify(self, finding: Finding, parameters: JsonObject) -> tuple[bool, JsonObject]:
        document, version = self._document(parameters)
        index, field, value = self._target(parameters)
        present = self._permission_present(document, index, field, value)
        state = {"permission_present": present, "version_id": version}
        return not present, state

    def _document(self, parameters: JsonObject) -> tuple[JsonObject, str]:
        arn = _required(parameters, "policy_arn")
        try:
            policy = self._iam.get_policy(PolicyArn=arn).get("Policy", {})
            version = policy.get("DefaultVersionId")
            response = self._iam.get_policy_version(PolicyArn=arn, VersionId=version)
            raw = response.get("PolicyVersion", {}).get("Document")
            if isinstance(raw, str):
                raw = json.loads(unquote(raw))
            if not isinstance(raw, dict) or not isinstance(version, str):
                raise TypeError
            return copy.deepcopy(raw), version
        except (BotoCoreError, ClientError, OSError, TypeError, json.JSONDecodeError) as exc:
            raise RemediationExecutionError("AWS returned an invalid IAM policy document") from exc

    @staticmethod
    def _target(parameters: JsonObject) -> tuple[int, str, str]:
        index = parameters.get("statement_index")
        field = parameters.get("permission_field")
        value = parameters.get("permission_value")
        if not isinstance(index, int) or isinstance(index, bool) or index < 0:
            raise RemediationExecutionError("statement_index must be a non-negative integer")
        if field not in {"Action", "Resource"}:
            raise RemediationExecutionError("permission_field must be Action or Resource")
        if not isinstance(value, str) or not value:
            raise RemediationExecutionError("permission_value must be a non-empty string")
        return index, field, value

    @staticmethod
    def _permission_present(document: JsonObject, index: int, field: str, value: str) -> bool:
        statements = document.get("Statement")
        if not isinstance(statements, list) or index >= len(statements):
            return False
        current = statements[index].get(field, [])
        return value in current if isinstance(current, list) else current == value
