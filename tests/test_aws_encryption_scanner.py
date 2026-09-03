"""Mocked tests for read-only AWS S3 and EBS encryption scanning."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any
from unittest.mock import MagicMock

import pytest
from botocore.exceptions import ClientError

from cloud_security_governance.aws import AWSEncryptionScanner
from cloud_security_governance.aws.encryption_scanner import (
    EBS_VOLUME_ENCRYPTION_RULE_ID,
    S3_BUCKET_ENCRYPTION_RULE_ID,
)
from cloud_security_governance.exceptions import AWSConfigurationError, AWSScanError
from cloud_security_governance.models import CloudProvider, ScanResult, Severity

NOW = datetime(2026, 9, 3, 12, 0, tzinfo=UTC)
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


def build_scanner(
    *,
    enabled_rules: set[str] | None = None,
    volume_pages: list[dict[str, Any]] | None = None,
) -> tuple[AWSEncryptionScanner, MagicMock, MagicMock, MagicMock, FakePaginator]:
    sts = MagicMock()
    sts.get_caller_identity.return_value = IDENTITY
    s3 = MagicMock()
    s3.list_buckets.return_value = {"Buckets": []}
    ec2 = MagicMock()
    volume_paginator = FakePaginator(volume_pages or [{"Volumes": []}])
    ec2.get_paginator.return_value = volume_paginator
    session = MagicMock()
    session.region_name = "us-east-1"
    clients = {"sts": sts, "s3": s3, "ec2": ec2}
    session.client.side_effect = lambda service, **_kwargs: clients[service]
    clock = MagicMock(side_effect=[NOW, NOW + timedelta(seconds=3)])
    scanner = AWSEncryptionScanner(
        enabled_rules=enabled_rules,
        session_factory=MagicMock(return_value=session),
        clock=clock,
    )
    return scanner, session, s3, ec2, volume_paginator


def test_compliant_s3_bucket_and_ebs_volume_produce_no_findings() -> None:
    scanner, _, s3, _, paginator = build_scanner(
        volume_pages=[
            {
                "Volumes": [
                    {
                        "VolumeId": "vol-0123456789abcdef0",
                        "Encrypted": True,
                        "AvailabilityZone": "us-east-1a",
                        "State": "in-use",
                    }
                ]
            }
        ]
    )
    s3.list_buckets.return_value = {"Buckets": [{"Name": "encrypted-audit-bucket"}]}
    s3.get_bucket_location.return_value = {"LocationConstraint": None}
    s3.get_bucket_encryption.return_value = {
        "ServerSideEncryptionConfiguration": {
            "Rules": [
                {
                    "ApplyServerSideEncryptionByDefault": {
                        "SSEAlgorithm": "aws:kms",
                        "KMSMasterKeyID": "alias/security-key",
                    }
                }
            ]
        }
    }

    result = scanner.scan()

    assert result.findings == []
    assert result.resources_scanned == 2
    assert result.account.provider is CloudProvider.AWS
    assert result.account.account_id == ACCOUNT_ID
    assert paginator.calls == [{}]
    s3.get_bucket_encryption.assert_called_once_with(Bucket="encrypted-audit-bucket")


def test_unencrypted_s3_bucket_creates_common_finding() -> None:
    scanner, _, s3, _, _ = build_scanner()
    s3.list_buckets.return_value = {"Buckets": [{"Name": "unencrypted-bucket"}]}
    s3.get_bucket_location.return_value = {"LocationConstraint": "EU"}
    s3.get_bucket_encryption.side_effect = ClientError(
        {
            "Error": {
                "Code": "ServerSideEncryptionConfigurationNotFoundError",
                "Message": "The server side encryption configuration was not found",
            }
        },
        "GetBucketEncryption",
    )

    result = scanner.scan()

    assert len(result.findings) == 1
    finding = result.findings[0]
    assert finding.rule_id == S3_BUCKET_ENCRYPTION_RULE_ID
    assert finding.severity is Severity.HIGH
    assert finding.remediation_available is True
    assert finding.detected_at == NOW
    assert finding.resource.resource_id == "arn:aws:s3:::unencrypted-bucket"
    assert finding.resource.region == "eu-west-1"
    assert finding.evidence == {"encryption_algorithms": []}


def test_unencrypted_ebs_volume_creates_common_finding() -> None:
    scanner, _, _, _, _ = build_scanner(
        volume_pages=[
            {
                "Volumes": [
                    {
                        "VolumeId": "vol-0fedcba9876543210",
                        "Encrypted": False,
                        "AvailabilityZone": "us-east-1b",
                        "State": "available",
                    }
                ]
            }
        ]
    )

    result = scanner.scan()

    assert len(result.findings) == 1
    finding = result.findings[0]
    assert finding.rule_id == EBS_VOLUME_ENCRYPTION_RULE_ID
    assert finding.severity is Severity.HIGH
    assert finding.remediation_available is True
    assert finding.detected_at == NOW
    assert finding.resource.resource_id == (
        f"arn:aws:ec2:us-east-1:{ACCOUNT_ID}:volume/vol-0fedcba9876543210"
    )
    assert finding.resource.metadata == {
        "availability_zone": "us-east-1b",
        "state": "available",
    }
    assert finding.evidence == {"encrypted": False}


def test_mixed_scan_returns_only_non_compliant_resources() -> None:
    scanner, _, s3, _, _ = build_scanner(
        volume_pages=[
            {
                "Volumes": [
                    {"VolumeId": "vol-encrypted", "Encrypted": True},
                    {"VolumeId": "vol-unencrypted", "Encrypted": False},
                ]
            }
        ]
    )
    s3.list_buckets.return_value = {
        "Buckets": [{"Name": "encrypted-bucket"}, {"Name": "unencrypted-bucket"}]
    }
    s3.get_bucket_location.side_effect = [
        {"LocationConstraint": "us-west-2"},
        {"LocationConstraint": "us-west-2"},
    ]
    s3.get_bucket_encryption.side_effect = [
        {
            "ServerSideEncryptionConfiguration": {
                "Rules": [
                    {"ApplyServerSideEncryptionByDefault": {"SSEAlgorithm": "AES256"}}
                ]
            }
        },
        ClientError(
            {
                "Error": {
                    "Code": "ServerSideEncryptionConfigurationNotFoundError",
                    "Message": "not configured",
                }
            },
            "GetBucketEncryption",
        ),
    ]

    result = scanner.scan()

    assert result.resources_scanned == 4
    assert {finding.rule_id for finding in result.findings} == {
        S3_BUCKET_ENCRYPTION_RULE_ID,
        EBS_VOLUME_ENCRYPTION_RULE_ID,
    }
    restored = ScanResult.model_validate_json(result.model_dump_json())
    assert restored == result


@pytest.mark.parametrize(
    ("enabled_rules", "expected_services"),
    [
        ({S3_BUCKET_ENCRYPTION_RULE_ID}, {"sts", "s3"}),
        ({EBS_VOLUME_ENCRYPTION_RULE_ID}, {"sts", "ec2"}),
        (set(), {"sts"}),
    ],
)
def test_only_configured_rules_are_scanned(
    enabled_rules: set[str], expected_services: set[str]
) -> None:
    scanner, session, _, _, _ = build_scanner(enabled_rules=enabled_rules)

    result = scanner.scan()

    created_services = {item.args[0] for item in session.client.call_args_list}
    assert created_services == expected_services
    assert result.findings == []
    assert result.resources_scanned == 0


def test_unknown_rule_is_rejected_before_clients_are_created() -> None:
    with pytest.raises(AWSConfigurationError, match="Unsupported AWS encryption rule"):
        AWSEncryptionScanner(
            enabled_rules={"aws.unknown.encryption-rule"},
            session_factory=MagicMock(),
        )


def test_ebs_rule_requires_a_resolved_region() -> None:
    session = MagicMock()
    session.region_name = None
    session.client.return_value = MagicMock()

    with pytest.raises(AWSConfigurationError, match="region is required"):
        AWSEncryptionScanner(
            enabled_rules={EBS_VOLUME_ENCRYPTION_RULE_ID},
            session_factory=MagicMock(return_value=session),
        )


def test_unexpected_s3_error_is_sanitized_not_reported_as_non_compliance() -> None:
    scanner, _, s3, _, _ = build_scanner()
    s3.list_buckets.return_value = {"Buckets": [{"Name": "restricted-bucket"}]}
    s3.get_bucket_location.return_value = {"LocationConstraint": "us-east-2"}
    s3.get_bucket_encryption.side_effect = ClientError(
        {
            "Error": {
                "Code": "AccessDenied",
                "Message": "sensitive upstream response details",
            }
        },
        "GetBucketEncryption",
    )

    with pytest.raises(AWSScanError, match="AccessDenied") as error:
        scanner.scan()

    assert "sensitive upstream response details" not in str(error.value)


def test_ebs_api_error_is_sanitized() -> None:
    scanner, _, _, ec2, _ = build_scanner()
    paginator = MagicMock()
    paginator.paginate.side_effect = ClientError(
        {"Error": {"Code": "UnauthorizedOperation", "Message": "internal details"}},
        "DescribeVolumes",
    )
    ec2.get_paginator.return_value = paginator

    with pytest.raises(AWSScanError, match="UnauthorizedOperation") as error:
        scanner.scan()

    assert "internal details" not in str(error.value)


@pytest.mark.parametrize(
    ("response", "message"),
    [
        ({"Buckets": "not-a-list"}, "invalid bucket list"),
        ({"Buckets": [{}]}, "invalid S3 bucket Name"),
    ],
)
def test_invalid_s3_responses_are_rejected(
    response: dict[str, Any], message: str
) -> None:
    scanner, _, s3, _, _ = build_scanner(
        enabled_rules={S3_BUCKET_ENCRYPTION_RULE_ID}
    )
    s3.list_buckets.return_value = response

    with pytest.raises(AWSScanError, match=message):
        scanner.scan()


def test_invalid_ebs_encryption_status_is_rejected() -> None:
    scanner, _, _, _, _ = build_scanner(
        enabled_rules={EBS_VOLUME_ENCRYPTION_RULE_ID},
        volume_pages=[{"Volumes": [{"VolumeId": "vol-example", "Encrypted": "false"}]}],
    )

    with pytest.raises(AWSScanError, match="invalid EBS encryption status"):
        scanner.scan()


def test_scanner_invokes_only_read_only_resource_operations() -> None:
    scanner, _, s3, ec2, _ = build_scanner()

    scanner.scan()

    s3_methods = {method_call[0] for method_call in s3.method_calls}
    ec2_methods = {method_call[0] for method_call in ec2.method_calls}
    assert s3_methods <= {"list_buckets"}
    assert ec2_methods <= {"get_paginator"}
    all_methods = s3_methods | ec2_methods
    assert not any(
        method.startswith(("create_", "delete_", "put_", "modify_", "enable_", "disable_"))
        for method in all_methods
    )

