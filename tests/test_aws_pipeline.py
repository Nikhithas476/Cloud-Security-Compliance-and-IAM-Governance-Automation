"""Tests for the complete normalized AWS scanning pipeline."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any
from unittest.mock import MagicMock

import pytest

from cloud_security_governance.aws import AWSScanner
from cloud_security_governance.aws.audit_services_scanner import (
    CLOUDTRAIL_LOGGING_RULE_ID,
    CONFIG_COMPLIANCE_RULE_ID,
)
from cloud_security_governance.aws.encryption_scanner import (
    EBS_VOLUME_ENCRYPTION_RULE_ID,
    S3_BUCKET_ENCRYPTION_RULE_ID,
)
from cloud_security_governance.exceptions import AWSScanError
from cloud_security_governance.models import (
    CloudAccount,
    CloudProvider,
    ScanResult,
)

NOW = datetime(2026, 9, 8, 12, 0, tzinfo=UTC)
ACCOUNT_ID = "123456789012"
IDENTITY = {
    "Account": ACCOUNT_ID,
    "Arn": f"arn:aws:iam::{ACCOUNT_ID}:user/security-auditor",
    "UserId": "AIDAEXAMPLESECURITY",
}


class FakePaginator:
    def __init__(self, pages: list[dict[str, Any]]) -> None:
        self.pages = pages

    def paginate(self, **_kwargs: Any) -> list[dict[str, Any]]:
        return self.pages


@pytest.fixture(autouse=True)
def clear_aws_environment(monkeypatch) -> None:
    for variable in ("AWS_PROFILE", "AWS_REGION", "AWS_DEFAULT_REGION", "AWS_ROLE_ARN"):
        monkeypatch.delenv(variable, raising=False)


def build_complete_pipeline() -> tuple[AWSScanner, MagicMock, dict[str, MagicMock]]:
    sts = MagicMock()
    sts.get_caller_identity.return_value = IDENTITY

    iam = MagicMock()
    iam_pages = {
        "list_policies": [{"Policies": []}],
        "list_users": [{"Users": []}],
        "list_roles": [{"Roles": []}],
        "list_groups": [{"Groups": []}],
    }
    iam.get_paginator.side_effect = lambda operation: FakePaginator(iam_pages[operation])
    iam.get_account_summary.return_value = {"SummaryMap": {"AccountAccessKeysPresent": 0}}

    s3 = MagicMock()
    s3.list_buckets.return_value = {"Buckets": [{"Name": "unencrypted-bucket"}]}
    s3.get_bucket_location.return_value = {"LocationConstraint": None}
    s3.get_bucket_encryption.side_effect = _missing_s3_encryption_error()

    ec2 = MagicMock()
    ec2.get_paginator.return_value = FakePaginator(
        [
            {
                "Volumes": [
                    {
                        "VolumeId": "vol-unencrypted",
                        "Encrypted": False,
                        "AvailabilityZone": "us-east-1a",
                    }
                ]
            }
        ]
    )

    cloudtrail = MagicMock()
    trail_arn = f"arn:aws:cloudtrail:us-east-1:{ACCOUNT_ID}:trail/security-trail"
    cloudtrail.describe_trails.return_value = {
        "trailList": [{"Name": "security-trail", "TrailARN": trail_arn, "HomeRegion": "us-east-1"}]
    }
    cloudtrail.get_trail_status.return_value = {"IsLogging": False}

    config = MagicMock()
    config.describe_configuration_recorders.return_value = {
        "ConfigurationRecorders": [{"name": "default"}]
    }
    config.describe_configuration_recorder_status.return_value = {
        "ConfigurationRecordersStatus": [{"name": "default", "recording": True}]
    }
    config.get_paginator.return_value = FakePaginator(
        [
            {
                "ComplianceByConfigRules": [
                    {
                        "ConfigRuleName": "required-tags",
                        "Compliance": {"ComplianceType": "NON_COMPLIANT"},
                    }
                ]
            }
        ]
    )

    clients = {
        "sts": sts,
        "iam": iam,
        "s3": s3,
        "ec2": ec2,
        "cloudtrail": cloudtrail,
        "config": config,
    }
    session = MagicMock()
    session.region_name = "us-east-1"
    session.client.side_effect = lambda service, **_kwargs: clients[service]
    session_factory = MagicMock(return_value=session)
    clock = MagicMock(side_effect=[NOW, NOW + timedelta(seconds=5)])
    scanner = AWSScanner(
        region="us-east-1",
        config_rule_names=["required-tags"],
        session_factory=session_factory,
        scan_clock=clock,
    )
    return scanner, session_factory, clients


def _missing_s3_encryption_error():
    from botocore.exceptions import ClientError

    return ClientError(
        {
            "Error": {
                "Code": "ServerSideEncryptionConfigurationNotFoundError",
                "Message": "not configured",
            }
        },
        "GetBucketEncryption",
    )


def test_complete_pipeline_returns_one_normalized_finding_list() -> None:
    scanner, session_factory, clients = build_complete_pipeline()

    result = scanner.scan()

    assert isinstance(result, ScanResult)
    assert {finding.rule_id for finding in result.findings} == {
        S3_BUCKET_ENCRYPTION_RULE_ID,
        EBS_VOLUME_ENCRYPTION_RULE_ID,
        CLOUDTRAIL_LOGGING_RULE_ID,
        CONFIG_COMPLIANCE_RULE_ID,
    }
    assert all(finding.resource.provider is CloudProvider.AWS for finding in result.findings)
    assert all(finding.resource.account_id == ACCOUNT_ID for finding in result.findings)
    assert result.account.account_id == ACCOUNT_ID
    assert result.resources_scanned == 6
    assert result.findings_count == 4
    assert result.started_at == NOW
    assert result.duration_seconds == 5.0
    assert result.errors == []
    assert session_factory.call_count == 1
    assert clients["sts"].get_caller_identity.call_count == 1


def test_pipeline_metadata_round_trips_through_json() -> None:
    scanner, _, _ = build_complete_pipeline()

    result = scanner.scan()
    restored = ScanResult.model_validate_json(result.model_dump_json())

    assert restored == result
    assert restored.scan_id == result.scan_id
    assert restored.findings_count == len(restored.findings)


def test_pipeline_rejects_a_result_for_a_different_account(monkeypatch) -> None:
    scanner, _, _ = build_complete_pipeline()
    original_scan = __import__(
        "cloud_security_governance.aws.iam_scanner", fromlist=["AWSIAMScanner"]
    ).AWSIAMScanner.scan

    def mismatched_scan(_scanner) -> ScanResult:
        return ScanResult(
            account=CloudAccount(
                account_id="999999999999",
                provider=CloudProvider.AWS,
                display_name="Different account",
            ),
            started_at=NOW,
            completed_at=NOW,
            resources_scanned=0,
        )

    monkeypatch.setattr(
        "cloud_security_governance.aws.iam_scanner.AWSIAMScanner.scan",
        mismatched_scan,
    )
    try:
        with pytest.raises(AWSScanError, match="different account"):
            scanner.scan()
    finally:
        monkeypatch.setattr(
            "cloud_security_governance.aws.iam_scanner.AWSIAMScanner.scan",
            original_scan,
        )
