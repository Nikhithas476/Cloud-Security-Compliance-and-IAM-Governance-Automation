"""Read-only AWS IAM security scanner."""

from __future__ import annotations

import json
from collections.abc import Callable, Iterator, Mapping
from datetime import UTC, datetime, timedelta
from typing import Any, NoReturn
from urllib.parse import unquote

import boto3
from boto3.session import Session
from botocore.exceptions import BotoCoreError, ClientError

from cloud_security_governance.aws.scanner import AWSScanner
from cloud_security_governance.exceptions import AWSConfigurationError, AWSScanError
from cloud_security_governance.models import (
    CloudAccount,
    CloudProvider,
    Finding,
    Resource,
    ScanResult,
    Severity,
)

ACTION_WILDCARD_RULE_ID = "aws.iam.policy.wildcard-action"
RESOURCE_WILDCARD_RULE_ID = "aws.iam.policy.wildcard-resource"
USER_MFA_RULE_ID = "aws.iam.user.mfa-enabled"
STALE_ACCESS_KEY_RULE_ID = "aws.iam.access-key.stale"
ROOT_ACCESS_KEY_RULE_ID = "aws.iam.root.access-key"


def _utc_now() -> datetime:
    return datetime.now(UTC)


class AWSIAMScanner(AWSScanner):
    """Evaluate AWS IAM configuration using non-mutating boto3 operations only."""

    def __init__(
        self,
        *,
        profile: str | None = None,
        region: str | None = None,
        role_arn: str | None = None,
        stale_key_days: int = 90,
        session_factory: Callable[..., Session] = boto3.Session,
        clock: Callable[[], datetime] = _utc_now,
    ) -> None:
        if stale_key_days <= 0:
            raise AWSConfigurationError("stale_key_days must be greater than zero")
        self.stale_key_days = stale_key_days
        self._clock = clock
        super().__init__(
            profile=profile,
            region=region,
            role_arn=role_arn,
            session_factory=session_factory,
        )
        try:
            self._iam = self._session.client("iam", region_name=self.region)
        except (BotoCoreError, OSError) as exc:
            raise AWSConfigurationError("The AWS IAM client could not be initialized") from exc

    def scan(self) -> ScanResult:
        """Run read-only IAM checks and return provider-neutral findings."""

        started_at = self._aware_utc(self._clock(), "scan timestamp")
        identity = self.get_caller_identity()
        account_id = identity["Account"]
        partition = identity["Arn"].split(":", maxsplit=2)[1]
        findings: list[Finding] = []
        resource_ids: set[str] = set()

        try:
            self._scan_managed_policies(account_id, findings, resource_ids, started_at)
            users = list(self._paginate("list_users", "Users"))
            self._scan_users(account_id, users, findings, resource_ids, started_at)
            self._scan_inline_role_policies(account_id, findings, resource_ids, started_at)
            self._scan_inline_group_policies(account_id, findings, resource_ids, started_at)
            self._scan_root(account_id, partition, findings, resource_ids, started_at)
        except ClientError as exc:
            self._raise_scan_client_error(exc)
        except (BotoCoreError, OSError) as exc:
            raise AWSScanError("The AWS IAM scan could not be completed") from exc

        completed_at = self._aware_utc(self._clock(), "scan timestamp")
        completed_at = max(completed_at, started_at)
        return ScanResult(
            account=CloudAccount(
                account_id=account_id,
                provider=CloudProvider.AWS,
                display_name=f"AWS account {account_id}",
            ),
            started_at=started_at,
            completed_at=completed_at,
            resources_scanned=len(resource_ids),
            findings=findings,
        )

    def _paginate(
        self, operation_name: str, result_key: str, **kwargs: Any
    ) -> Iterator[Mapping[str, Any]]:
        paginator = self._iam.get_paginator(operation_name)
        for page in paginator.paginate(**kwargs):
            items = page.get(result_key, [])
            if not isinstance(items, list):
                raise AWSScanError(f"AWS IAM returned an invalid {result_key} response")
            for item in items:
                if not isinstance(item, Mapping):
                    raise AWSScanError(f"AWS IAM returned an invalid {result_key} item")
                yield item

    def _scan_managed_policies(
        self,
        account_id: str,
        findings: list[Finding],
        resource_ids: set[str],
        detected_at: datetime,
    ) -> None:
        for policy in self._paginate("list_policies", "Policies", Scope="Local"):
            arn = self._required_string(policy, "Arn", "managed policy")
            name = self._required_string(policy, "PolicyName", "managed policy")
            version_id = self._required_string(policy, "DefaultVersionId", "managed policy")
            response = self._iam.get_policy_version(PolicyArn=arn, VersionId=version_id)
            version = response.get("PolicyVersion", {})
            if not isinstance(version, Mapping) or "Document" not in version:
                raise AWSScanError("AWS IAM returned an invalid managed policy version")
            resource = Resource(
                resource_id=arn,
                provider=CloudProvider.AWS,
                account_id=account_id,
                resource_type="AWS::IAM::ManagedPolicy",
                name=name,
                metadata={"policy_type": "customer_managed", "version_id": version_id},
            )
            resource_ids.add(resource.resource_id)
            findings.extend(self._evaluate_policy(resource, version["Document"], detected_at))

    def _scan_users(
        self,
        account_id: str,
        users: list[Mapping[str, Any]],
        findings: list[Finding],
        resource_ids: set[str],
        detected_at: datetime,
    ) -> None:
        for user in users:
            user_name = self._required_string(user, "UserName", "IAM user")
            user_arn = self._required_string(user, "Arn", "IAM user")
            user_resource = Resource(
                resource_id=user_arn,
                provider=CloudProvider.AWS,
                account_id=account_id,
                resource_type="AWS::IAM::User",
                name=user_name,
            )
            resource_ids.add(user_resource.resource_id)

            mfa_devices = list(
                self._paginate("list_mfa_devices", "MFADevices", UserName=user_name)
            )
            if not mfa_devices:
                findings.append(
                    Finding(
                        rule_id=USER_MFA_RULE_ID,
                        resource=user_resource,
                        title="IAM user does not have MFA enabled",
                        description=f"IAM user {user_name} has no assigned MFA device.",
                        severity=Severity.HIGH,
                        remediation_available=True,
                        evidence={"mfa_device_count": 0},
                        detected_at=detected_at,
                    )
                )

            self._scan_access_keys(
                account_id,
                user_name,
                user_arn,
                findings,
                resource_ids,
                detected_at,
            )
            self._scan_inline_policies(
                account_id=account_id,
                entity_type="user",
                entity_name=user_name,
                list_operation="list_user_policies",
                get_operation="get_user_policy",
                list_argument="UserName",
                result_key="PolicyNames",
                findings=findings,
                resource_ids=resource_ids,
                detected_at=detected_at,
            )

    def _scan_access_keys(
        self,
        account_id: str,
        user_name: str,
        user_arn: str,
        findings: list[Finding],
        resource_ids: set[str],
        detected_at: datetime,
    ) -> None:
        threshold = detected_at - timedelta(days=self.stale_key_days)
        for key in self._paginate("list_access_keys", "AccessKeyMetadata", UserName=user_name):
            access_key_id = self._required_string(key, "AccessKeyId", "access key")
            created_at = self._required_datetime(key, "CreateDate", "access key")
            key_resource = Resource(
                resource_id=f"{user_arn}/access-key/{access_key_id}",
                provider=CloudProvider.AWS,
                account_id=account_id,
                resource_type="AWS::IAM::AccessKey",
                name=access_key_id,
                metadata={"user_name": user_name, "status": str(key.get("Status", "Unknown"))},
            )
            resource_ids.add(key_resource.resource_id)
            last_used_response = self._iam.get_access_key_last_used(AccessKeyId=access_key_id)
            last_used_details = last_used_response.get("AccessKeyLastUsed", {})
            if not isinstance(last_used_details, Mapping):
                raise AWSScanError("AWS IAM returned invalid access-key last-used details")
            last_used_value = last_used_details.get("LastUsedDate")
            last_used_at = (
                self._aware_utc(last_used_value, "access-key last-used timestamp")
                if isinstance(last_used_value, datetime)
                else None
            )
            activity_at = last_used_at or created_at
            if activity_at >= threshold:
                continue

            age_days = (detected_at - activity_at).days
            activity_description = (
                f"was last used {age_days} days ago"
                if last_used_at is not None
                else f"has never been used and was created {age_days} days ago"
            )
            findings.append(
                Finding(
                    rule_id=STALE_ACCESS_KEY_RULE_ID,
                    resource=key_resource,
                    title="IAM access key is stale",
                    description=(
                        f"Access key for IAM user {user_name} {activity_description}, exceeding "
                        f"the {self.stale_key_days}-day threshold."
                    ),
                    severity=Severity.HIGH,
                    remediation_available=True,
                    evidence={
                        "created_at": created_at.isoformat(),
                        "last_used_at": last_used_at.isoformat() if last_used_at else None,
                        "stale_days": age_days,
                        "threshold_days": self.stale_key_days,
                    },
                    detected_at=detected_at,
                )
            )

    def _scan_inline_role_policies(
        self,
        account_id: str,
        findings: list[Finding],
        resource_ids: set[str],
        detected_at: datetime,
    ) -> None:
        for role in self._paginate("list_roles", "Roles"):
            role_name = self._required_string(role, "RoleName", "IAM role")
            self._scan_inline_policies(
                account_id=account_id,
                entity_type="role",
                entity_name=role_name,
                list_operation="list_role_policies",
                get_operation="get_role_policy",
                list_argument="RoleName",
                result_key="PolicyNames",
                findings=findings,
                resource_ids=resource_ids,
                detected_at=detected_at,
            )

    def _scan_inline_group_policies(
        self,
        account_id: str,
        findings: list[Finding],
        resource_ids: set[str],
        detected_at: datetime,
    ) -> None:
        for group in self._paginate("list_groups", "Groups"):
            group_name = self._required_string(group, "GroupName", "IAM group")
            self._scan_inline_policies(
                account_id=account_id,
                entity_type="group",
                entity_name=group_name,
                list_operation="list_group_policies",
                get_operation="get_group_policy",
                list_argument="GroupName",
                result_key="PolicyNames",
                findings=findings,
                resource_ids=resource_ids,
                detected_at=detected_at,
            )

    def _scan_inline_policies(
        self,
        *,
        account_id: str,
        entity_type: str,
        entity_name: str,
        list_operation: str,
        get_operation: str,
        list_argument: str,
        result_key: str,
        findings: list[Finding],
        resource_ids: set[str],
        detected_at: datetime,
    ) -> None:
        arguments = {list_argument: entity_name}
        paginator = self._iam.get_paginator(list_operation)
        for page in paginator.paginate(**arguments):
            policy_names = page.get(result_key, [])
            if not isinstance(policy_names, list):
                raise AWSScanError(f"AWS IAM returned an invalid {result_key} response")
            for policy_name in policy_names:
                if not isinstance(policy_name, str) or not policy_name.strip():
                    raise AWSScanError("AWS IAM returned an invalid inline policy name")
                get_arguments = {list_argument: entity_name, "PolicyName": policy_name}
                response = getattr(self._iam, get_operation)(**get_arguments)
                if "PolicyDocument" not in response:
                    raise AWSScanError("AWS IAM returned an invalid inline policy document")
                resource = Resource(
                    resource_id=f"iam-inline-policy:{entity_type}:{entity_name}:{policy_name}",
                    provider=CloudProvider.AWS,
                    account_id=account_id,
                    resource_type=f"AWS::IAM::Inline{entity_type.title()}Policy",
                    name=policy_name,
                    metadata={
                        "policy_type": "inline",
                        "parent_type": entity_type,
                        "parent_name": entity_name,
                    },
                )
                resource_ids.add(resource.resource_id)
                findings.extend(
                    self._evaluate_policy(resource, response["PolicyDocument"], detected_at)
                )

    def _scan_root(
        self,
        account_id: str,
        partition: str,
        findings: list[Finding],
        resource_ids: set[str],
        detected_at: datetime,
    ) -> None:
        summary = self._iam.get_account_summary().get("SummaryMap", {})
        if not isinstance(summary, Mapping):
            raise AWSScanError("AWS IAM returned an invalid account summary")
        root_key_count = summary.get("AccountAccessKeysPresent", 0)
        if not isinstance(root_key_count, int) or isinstance(root_key_count, bool):
            raise AWSScanError("AWS IAM returned an invalid root access-key count")
        root_resource = Resource(
            resource_id=f"arn:{partition}:iam::{account_id}:root",
            provider=CloudProvider.AWS,
            account_id=account_id,
            resource_type="AWS::IAM::RootUser",
            name="root",
        )
        resource_ids.add(root_resource.resource_id)
        if root_key_count > 0:
            findings.append(
                Finding(
                    rule_id=ROOT_ACCESS_KEY_RULE_ID,
                    resource=root_resource,
                    title="Root account has active access keys",
                    description=(
                        f"The AWS root account has {root_key_count} access key(s). Root access "
                        "keys create a critical account-compromise risk."
                    ),
                    severity=Severity.CRITICAL,
                    remediation_available=True,
                    evidence={"root_access_key_count": root_key_count},
                    detected_at=detected_at,
                )
            )

    def _evaluate_policy(
        self, resource: Resource, document_value: Any, detected_at: datetime
    ) -> list[Finding]:
        document = self._decode_policy_document(document_value)
        statements = document.get("Statement", [])
        if isinstance(statements, Mapping):
            statements = [statements]
        if not isinstance(statements, list):
            raise AWSScanError("AWS IAM policy Statement must be an object or list")

        findings: list[Finding] = []
        for index, statement in enumerate(statements):
            if not isinstance(statement, Mapping):
                raise AWSScanError("AWS IAM policy contains an invalid statement")
            if str(statement.get("Effect", "")).casefold() != "allow":
                continue
            evidence = {
                "policy_type": resource.metadata.get("policy_type", "unknown"),
                "statement_index": index,
            }
            if self._contains_full_wildcard(statement.get("Action")):
                findings.append(
                    Finding(
                        rule_id=ACTION_WILDCARD_RULE_ID,
                        resource=resource,
                        title="IAM policy allows all actions",
                        description=(
                            f"IAM policy {resource.name} contains an Allow statement with "
                            "Action: *, granting unrestricted API actions."
                        ),
                        severity=Severity.CRITICAL,
                        remediation_available=True,
                        evidence=evidence,
                        detected_at=detected_at,
                    )
                )
            if self._contains_full_wildcard(statement.get("Resource")):
                findings.append(
                    Finding(
                        rule_id=RESOURCE_WILDCARD_RULE_ID,
                        resource=resource,
                        title="IAM policy applies to all resources",
                        description=(
                            f"IAM policy {resource.name} contains an Allow statement with "
                            "Resource: *, allowing access without resource-level restriction."
                        ),
                        severity=Severity.HIGH,
                        remediation_available=True,
                        evidence=evidence,
                        detected_at=detected_at,
                    )
                )
        return findings

    @staticmethod
    def _decode_policy_document(value: Any) -> Mapping[str, Any]:
        if isinstance(value, Mapping):
            return value
        if isinstance(value, str):
            try:
                decoded = json.loads(unquote(value))
            except (json.JSONDecodeError, UnicodeDecodeError) as exc:
                raise AWSScanError("AWS IAM returned an invalid policy document") from exc
            if isinstance(decoded, Mapping):
                return decoded
        raise AWSScanError("AWS IAM returned an invalid policy document")

    @staticmethod
    def _contains_full_wildcard(value: Any) -> bool:
        if isinstance(value, str):
            return value.strip() == "*"
        if isinstance(value, list):
            return any(isinstance(item, str) and item.strip() == "*" for item in value)
        return False

    @classmethod
    def _required_datetime(
        cls, value: Mapping[str, Any], key: str, context: str
    ) -> datetime:
        result = value.get(key)
        if not isinstance(result, datetime):
            raise AWSScanError(f"AWS IAM returned an invalid {context} {key}")
        return cls._aware_utc(result, f"{context} {key}")

    @staticmethod
    def _required_string(value: Mapping[str, Any], key: str, context: str) -> str:
        result = value.get(key)
        if not isinstance(result, str) or not result.strip():
            raise AWSScanError(f"AWS IAM returned an invalid {context} {key}")
        return result.strip()

    @staticmethod
    def _aware_utc(value: datetime, context: str) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise AWSScanError(f"AWS returned a timezone-naive {context}")
        return value.astimezone(UTC)

    @staticmethod
    def _raise_scan_client_error(error: ClientError) -> NoReturn:
        details = error.response.get("Error", {})
        code = details.get("Code") if isinstance(details, Mapping) else None
        safe_code = str(code) if code else "UnknownError"
        raise AWSScanError(f"The AWS IAM scan could not be completed ({safe_code})") from error
