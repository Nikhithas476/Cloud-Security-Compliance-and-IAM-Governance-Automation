"""Comprehensive mocked tests for the read-only AWS IAM scanner."""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from typing import Any
from unittest.mock import MagicMock
from urllib.parse import quote

import pytest
from botocore.exceptions import ClientError

from cloud_security_governance.aws import AWSIAMScanner
from cloud_security_governance.aws.iam_scanner import (
    ACTION_WILDCARD_RULE_ID,
    RESOURCE_WILDCARD_RULE_ID,
    ROOT_ACCESS_KEY_RULE_ID,
    STALE_ACCESS_KEY_RULE_ID,
    USER_MFA_RULE_ID,
)
from cloud_security_governance.exceptions import AWSConfigurationError, AWSScanError
from cloud_security_governance.models import CloudProvider, ScanResult, Severity

NOW = datetime(2026, 9, 2, 12, 0, tzinfo=UTC)
ACCOUNT_ID = "123456789012"
IDENTITY = {
    "Account": ACCOUNT_ID,
    "Arn": f"arn:aws:iam::{ACCOUNT_ID}:user/security-auditor",
    "UserId": "AIDAEXAMPLESECURITY",
}


class FakePaginator:
    def __init__(self, pages: list[dict[str, Any]]) -> None:
        self.pages = pages
        self.calls: list[dict[str, Any]] = []

    def paginate(self, **kwargs: Any) -> list[dict[str, Any]]:
        self.calls.append(kwargs)
        return self.pages


@pytest.fixture(autouse=True)
def clear_aws_environment(monkeypatch) -> None:
    for variable in ("AWS_PROFILE", "AWS_REGION", "AWS_DEFAULT_REGION", "AWS_ROLE_ARN"):
        monkeypatch.delenv(variable, raising=False)


def default_pages() -> dict[str, list[dict[str, Any]]]:
    return {
        "list_policies": [{"Policies": []}],
        "list_users": [{"Users": []}],
        "list_mfa_devices": [{"MFADevices": []}],
        "list_access_keys": [{"AccessKeyMetadata": []}],
        "list_user_policies": [{"PolicyNames": []}],
        "list_roles": [{"Roles": []}],
        "list_role_policies": [{"PolicyNames": []}],
        "list_groups": [{"Groups": []}],
        "list_group_policies": [{"PolicyNames": []}],
    }


def build_scanner(
    page_overrides: dict[str, list[dict[str, Any]]] | None = None,
) -> tuple[AWSIAMScanner, MagicMock, dict[str, FakePaginator]]:
    pages = default_pages()
    pages.update(page_overrides or {})
    paginators = {name: FakePaginator(value) for name, value in pages.items()}

    iam = MagicMock()
    iam.get_paginator.side_effect = lambda operation: paginators[operation]
    iam.get_account_summary.return_value = {
        "SummaryMap": {"AccountAccessKeysPresent": 0}
    }
    sts = MagicMock()
    sts.get_caller_identity.return_value = IDENTITY
    session = MagicMock()
    session.client.side_effect = lambda service, **_kwargs: sts if service == "sts" else iam
    clock = MagicMock(side_effect=[NOW, NOW + timedelta(seconds=2)])
    scanner = AWSIAMScanner(
        session_factory=MagicMock(return_value=session),
        clock=clock,
    )
    return scanner, iam, paginators


def test_managed_policy_wildcards_create_common_findings() -> None:
    policy_arn = f"arn:aws:iam::{ACCOUNT_ID}:policy/AdministratorPolicy"
    scanner, iam, paginators = build_scanner(
        {
            "list_policies": [
                {
                    "Policies": [
                        {
                            "Arn": policy_arn,
                            "PolicyName": "AdministratorPolicy",
                            "DefaultVersionId": "v3",
                        }
                    ]
                }
            ]
        }
    )
    iam.get_policy_version.return_value = {
        "PolicyVersion": {
            "Document": {
                "Version": "2012-10-17",
                "Statement": {"Effect": "Allow", "Action": "*", "Resource": ["*"]},
            }
        }
    }

    result = scanner.scan()

    assert isinstance(result, ScanResult)
    assert {finding.rule_id for finding in result.findings} == {
        ACTION_WILDCARD_RULE_ID,
        RESOURCE_WILDCARD_RULE_ID,
    }
    assert {finding.severity for finding in result.findings} == {
        Severity.CRITICAL,
        Severity.HIGH,
    }
    assert all(finding.remediation_available for finding in result.findings)
    assert all(finding.detected_at == NOW for finding in result.findings)
    assert all(finding.resource.resource_id == policy_arn for finding in result.findings)
    assert result.account.provider is CloudProvider.AWS
    assert result.account.account_id == ACCOUNT_ID
    assert result.resources_scanned == 2  # Managed policy and root identity.
    assert paginators["list_policies"].calls == [{"Scope": "Local"}]
    iam.get_policy_version.assert_called_once_with(PolicyArn=policy_arn, VersionId="v3")


def test_deny_wildcards_and_partial_wildcards_are_not_flagged() -> None:
    scanner, iam, _ = build_scanner(
        {
            "list_policies": [
                {
                    "Policies": [
                        {
                            "Arn": f"arn:aws:iam::{ACCOUNT_ID}:policy/Guardrail",
                            "PolicyName": "Guardrail",
                            "DefaultVersionId": "v1",
                        }
                    ]
                }
            ]
        }
    )
    iam.get_policy_version.return_value = {
        "PolicyVersion": {
            "Document": {
                "Statement": [
                    {"Effect": "Deny", "Action": "*", "Resource": "*"},
                    {"Effect": "Allow", "Action": "s3:*", "Resource": "bucket-*"},
                ]
            }
        }
    }

    result = scanner.scan()

    assert result.findings == []


def test_url_encoded_inline_user_policy_is_evaluated() -> None:
    scanner, iam, _ = build_scanner(
        {
            "list_users": [
                {
                    "Users": [
                        {
                            "UserName": "alice",
                            "Arn": f"arn:aws:iam::{ACCOUNT_ID}:user/alice",
                        }
                    ]
                }
            ],
            "list_mfa_devices": [{"MFADevices": [{"SerialNumber": "mfa-device"}]}],
            "list_user_policies": [{"PolicyNames": ["InlineAuditPolicy"]}],
        }
    )
    iam.get_user_policy.return_value = {
        "PolicyDocument": quote(
            json.dumps(
                {
                    "Statement": {
                        "Effect": "Allow",
                        "Action": ["iam:GetUser"],
                        "Resource": "*",
                    }
                }
            )
        )
    }

    result = scanner.scan()

    assert [finding.rule_id for finding in result.findings] == [
        RESOURCE_WILDCARD_RULE_ID
    ]
    finding = result.findings[0]
    assert finding.resource.resource_type == "AWS::IAM::InlineUserPolicy"
    assert finding.resource.metadata["parent_name"] == "alice"
    iam.get_user_policy.assert_called_once_with(
        UserName="alice", PolicyName="InlineAuditPolicy"
    )


@pytest.mark.parametrize(
    ("entity_key", "entity_name", "list_operation", "get_operation", "resource_type"),
    [
        ("Roles", "AuditRole", "list_role_policies", "get_role_policy", "InlineRolePolicy"),
        (
            "Groups",
            "Developers",
            "list_group_policies",
            "get_group_policy",
            "InlineGroupPolicy",
        ),
    ],
)
def test_inline_role_and_group_policies_are_evaluated(
    entity_key: str,
    entity_name: str,
    list_operation: str,
    get_operation: str,
    resource_type: str,
) -> None:
    collection_operation = "list_roles" if entity_key == "Roles" else "list_groups"
    name_key = "RoleName" if entity_key == "Roles" else "GroupName"
    scanner, iam, _ = build_scanner(
        {
            collection_operation: [{entity_key: [{name_key: entity_name}]}],
            list_operation: [{"PolicyNames": ["InlinePolicy"]}],
        }
    )
    getattr(iam, get_operation).return_value = {
        "PolicyDocument": {
            "Statement": {"Effect": "Allow", "Action": "*", "Resource": "named-resource"}
        }
    }

    result = scanner.scan()

    assert [finding.rule_id for finding in result.findings] == [ACTION_WILDCARD_RULE_ID]
    assert result.findings[0].resource.resource_type == f"AWS::IAM::{resource_type}"


def test_user_without_mfa_creates_high_severity_finding() -> None:
    scanner, _, _ = build_scanner(
        {
            "list_users": [
                {
                    "Users": [
                        {
                            "UserName": "bob",
                            "Arn": f"arn:aws:iam::{ACCOUNT_ID}:user/bob",
                        }
                    ]
                }
            ]
        }
    )

    result = scanner.scan()

    assert len(result.findings) == 1
    finding = result.findings[0]
    assert finding.rule_id == USER_MFA_RULE_ID
    assert finding.severity is Severity.HIGH
    assert finding.resource.name == "bob"
    assert finding.evidence == {"mfa_device_count": 0}


def test_stale_keys_use_last_used_date_or_creation_date() -> None:
    user_arn = f"arn:aws:iam::{ACCOUNT_ID}:user/carol"
    scanner, iam, _ = build_scanner(
        {
            "list_users": [{"Users": [{"UserName": "carol", "Arn": user_arn}]}],
            "list_mfa_devices": [{"MFADevices": [{"SerialNumber": "mfa-device"}]}],
            "list_access_keys": [
                {
                    "AccessKeyMetadata": [
                        {
                            "AccessKeyId": "OLDUSEDKEY",
                            "CreateDate": NOW - timedelta(days=200),
                            "Status": "Active",
                        },
                        {
                            "AccessKeyId": "NEVERUSEDKEY",
                            "CreateDate": NOW - timedelta(days=100),
                            "Status": "Inactive",
                        },
                        {
                            "AccessKeyId": "RECENTKEY",
                            "CreateDate": NOW - timedelta(days=200),
                            "Status": "Active",
                        },
                    ]
                }
            ],
        }
    )
    iam.get_access_key_last_used.side_effect = [
        {"AccessKeyLastUsed": {"LastUsedDate": NOW - timedelta(days=91)}},
        {"AccessKeyLastUsed": {}},
        {"AccessKeyLastUsed": {"LastUsedDate": NOW - timedelta(days=2)}},
    ]

    result = scanner.scan()

    stale_findings = [
        finding for finding in result.findings if finding.rule_id == STALE_ACCESS_KEY_RULE_ID
    ]
    assert {finding.resource.name for finding in stale_findings} == {
        "OLDUSEDKEY",
        "NEVERUSEDKEY",
    }
    never_used = next(
        finding for finding in stale_findings if finding.resource.name == "NEVERUSEDKEY"
    )
    assert never_used.evidence["last_used_at"] is None
    assert never_used.evidence["stale_days"] == 100
    assert result.resources_scanned == 5  # User, three keys, and root identity.


def test_key_exactly_at_threshold_is_not_stale() -> None:
    scanner, iam, _ = build_scanner(
        {
            "list_users": [
                {
                    "Users": [
                        {
                            "UserName": "dana",
                            "Arn": f"arn:aws:iam::{ACCOUNT_ID}:user/dana",
                        }
                    ]
                }
            ],
            "list_mfa_devices": [{"MFADevices": [{"SerialNumber": "mfa-device"}]}],
            "list_access_keys": [
                {
                    "AccessKeyMetadata": [
                        {
                            "AccessKeyId": "THRESHOLDKEY",
                            "CreateDate": NOW - timedelta(days=120),
                            "Status": "Active",
                        }
                    ]
                }
            ],
        }
    )
    iam.get_access_key_last_used.return_value = {
        "AccessKeyLastUsed": {"LastUsedDate": NOW - timedelta(days=90)}
    }

    result = scanner.scan()

    assert result.findings == []


def test_root_access_keys_create_critical_finding() -> None:
    scanner, iam, _ = build_scanner()
    iam.get_account_summary.return_value = {
        "SummaryMap": {"AccountAccessKeysPresent": 1}
    }

    result = scanner.scan()

    assert len(result.findings) == 1
    finding = result.findings[0]
    assert finding.rule_id == ROOT_ACCESS_KEY_RULE_ID
    assert finding.severity is Severity.CRITICAL
    assert finding.resource.resource_id == f"arn:aws:iam::{ACCOUNT_ID}:root"
    assert finding.evidence == {"root_access_key_count": 1}


def test_scan_result_round_trips_through_json() -> None:
    scanner, iam, _ = build_scanner()
    iam.get_account_summary.return_value = {
        "SummaryMap": {"AccountAccessKeysPresent": 1}
    }

    result = scanner.scan()
    restored = ScanResult.model_validate_json(result.model_dump_json())

    assert restored == result
    assert restored.findings[0].remediation_available is True


def test_scan_errors_are_sanitized() -> None:
    scanner, iam, _ = build_scanner()
    iam.get_account_summary.side_effect = ClientError(
        {"Error": {"Code": "AccessDenied", "Message": "sensitive AWS response details"}},
        "GetAccountSummary",
    )

    with pytest.raises(AWSScanError, match="AccessDenied") as error:
        scanner.scan()

    assert "sensitive AWS response details" not in str(error.value)


def test_invalid_stale_key_threshold_is_rejected() -> None:
    with pytest.raises(AWSConfigurationError, match="greater than zero"):
        AWSIAMScanner(stale_key_days=0, session_factory=MagicMock())


def test_only_read_only_iam_methods_are_invoked() -> None:
    scanner, iam, _ = build_scanner()

    scanner.scan()

    invoked_methods = {method_call[0] for method_call in iam.method_calls}
    assert invoked_methods <= {"get_paginator", "get_account_summary"}
    assert not any(
        method.startswith(("create_", "delete_", "update_", "put_", "attach_", "detach_"))
        for method in invoked_methods
    )

