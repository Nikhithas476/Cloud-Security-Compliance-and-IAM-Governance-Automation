"""Mocked tests for DynamoDB workflow persistence."""

from __future__ import annotations

from datetime import UTC, datetime
from unittest.mock import MagicMock

import pytest
from botocore.exceptions import ClientError

from cloud_security_governance.exceptions import RecordNotFoundError, StorageError
from cloud_security_governance.models import (
    CloudAccount,
    CloudProvider,
    Finding,
    FindingStatus,
    MultiCloudScanResult,
    RemediationAction,
    ScanResult,
    Severity,
)
from cloud_security_governance.storage import DynamoDBStorage, FindingStorage

NOW = datetime(2026, 9, 24, 12, 0, tzinfo=UTC)
ACCOUNT_ID = "123456789012"


def sample_finding() -> Finding:
    from cloud_security_governance.models import Resource

    return Finding(
        rule_id="aws.s3.bucket.encryption-enabled",
        resource=Resource(
            resource_id="arn:aws:s3:::audit-bucket",
            provider=CloudProvider.AWS,
            account_id=ACCOUNT_ID,
            resource_type="s3-bucket",
            name="audit-bucket",
        ),
        title="S3 bucket encryption missing",
        description="The bucket does not have default encryption configured.",
        severity=Severity.HIGH,
        remediation_available=True,
        detected_at=NOW,
    )


def sample_scan(finding: Finding) -> ScanResult:
    return ScanResult(
        account=CloudAccount(
            account_id=ACCOUNT_ID,
            provider=CloudProvider.AWS,
            display_name="AWS audit account",
        ),
        started_at=NOW,
        completed_at=NOW,
        resources_scanned=1,
        findings=[finding],
    )


def build_storage() -> tuple[DynamoDBStorage, MagicMock, MagicMock]:
    table = MagicMock()
    dynamodb = MagicMock()
    dynamodb.Table.return_value = table
    factory = MagicMock(return_value=dynamodb)
    storage = DynamoDBStorage(
        table_name="security-governance",
        region="us-east-1",
        resource_factory=factory,
        clock=MagicMock(return_value=NOW),
    )
    return storage, table, factory


def test_implements_storage_interface_without_credential_parameters() -> None:
    storage, _, factory = build_storage()

    assert isinstance(storage, FindingStorage)
    factory.assert_called_once_with("dynamodb", region_name="us-east-1")
    assert "aws_access_key_id" not in factory.call_args.kwargs
    assert "aws_secret_access_key" not in factory.call_args.kwargs


def test_save_finding_uses_single_table_keys_and_findings_index() -> None:
    storage, table, _ = build_storage()
    finding = sample_finding()

    storage.save_finding(finding)

    item = table.put_item.call_args.kwargs["Item"]
    assert item["PK"] == f"FINDING#{finding.finding_id}"
    assert item["SK"] == "METADATA"
    assert item["GSI1PK"] == "FINDINGS"
    assert item["GSI1SK"] == f"{NOW.isoformat()}#{finding.finding_id}"
    assert item["provider"] == "aws"
    assert item["status"] == "open"
    assert item["payload"]["finding_id"] == str(finding.finding_id)


def test_get_finding_returns_model_or_none() -> None:
    storage, table, _ = build_storage()
    finding = sample_finding()
    table.get_item.return_value = {"Item": {"payload": storage._serialize(finding)}}

    restored = storage.get_finding(finding.finding_id)

    assert restored == finding
    table.get_item.assert_called_once_with(
        Key={"PK": f"FINDING#{finding.finding_id}", "SK": "METADATA"},
        ConsistentRead=True,
    )
    table.get_item.return_value = {}
    assert storage.get_finding(finding.finding_id) is None


def test_list_findings_supports_filters_pagination_and_limit() -> None:
    storage, table, _ = build_storage()
    first = sample_finding()
    second = first.model_copy(update={"finding_id": __import__("uuid").uuid4()})
    table.query.side_effect = [
        {
            "Items": [{"payload": storage._serialize(first)}],
            "LastEvaluatedKey": {"PK": "next"},
        },
        {"Items": [{"payload": storage._serialize(second)}]},
    ]

    findings = storage.list_findings(
        provider=CloudProvider.AWS,
        status=FindingStatus.OPEN,
        limit=2,
    )

    assert findings == [first, second]
    assert table.query.call_count == 2
    first_call = table.query.call_args_list[0].kwargs
    assert first_call["IndexName"] == "GSI1"
    assert first_call["FilterExpression"] == "provider = :provider AND #status = :status"
    assert table.query.call_args_list[1].kwargs["ExclusiveStartKey"] == {"PK": "next"}


def test_update_finding_status_returns_updated_finding() -> None:
    storage, table, _ = build_storage()
    finding = sample_finding()
    updated = finding.model_copy(update={"status": FindingStatus.ACKNOWLEDGED, "updated_at": NOW})
    table.update_item.return_value = {"Attributes": {"payload": storage._serialize(updated)}}

    result = storage.update_finding_status(finding.finding_id, FindingStatus.ACKNOWLEDGED)

    assert result == updated
    call = table.update_item.call_args.kwargs
    assert call["ConditionExpression"] == "attribute_exists(PK)"
    assert call["ExpressionAttributeValues"][":status"] == "acknowledged"


def test_update_missing_finding_raises_not_found() -> None:
    storage, table, _ = build_storage()
    finding = sample_finding()
    table.update_item.side_effect = ClientError(
        {"Error": {"Code": "ConditionalCheckFailedException", "Message": "missing"}},
        "UpdateItem",
    )

    with pytest.raises(RecordNotFoundError, match="was not found"):
        storage.update_finding_status(finding.finding_id, FindingStatus.RESOLVED)


def test_save_and_get_scan_metadata() -> None:
    storage, table, _ = build_storage()
    scan = sample_scan(sample_finding())

    storage.save_scan_metadata(scan)

    item = table.put_item.call_args.kwargs["Item"]
    assert item["PK"] == f"SCAN#{scan.scan_id}"
    assert item["SK"] == "METADATA"
    assert item["model_type"] == "cloud"
    table.get_item.return_value = {"Item": item}
    assert storage.get_scan_metadata(scan.scan_id) == scan


def test_save_and_get_multi_cloud_scan_metadata() -> None:
    storage, table, _ = build_storage()
    cloud_scan = sample_scan(sample_finding())
    scan = MultiCloudScanResult(
        started_at=NOW,
        completed_at=NOW,
        results=[cloud_scan],
        findings=cloud_scan.findings,
        resources_scanned=cloud_scan.resources_scanned,
    )

    storage.save_scan_metadata(scan)

    item = table.put_item.call_args.kwargs["Item"]
    assert item["model_type"] == "multi_cloud"
    table.get_item.return_value = {"Item": item}
    assert storage.get_scan_metadata(scan.scan_id) == scan


def test_save_remediation_history_uses_finding_partition() -> None:
    storage, table, _ = build_storage()
    finding = sample_finding()
    action = RemediationAction(
        finding_id=finding.finding_id,
        action_type="manual-review",
        description="Review and enable default bucket encryption.",
        created_at=NOW,
    )

    storage.save_remediation_history(action)

    item = table.put_item.call_args.kwargs["Item"]
    assert item["PK"] == f"FINDING#{finding.finding_id}"
    assert item["SK"] == f"REMEDIATION#{NOW.isoformat()}#{action.action_id}"
    assert item["record_type"] == "remediation"


def test_dynamodb_errors_are_sanitized() -> None:
    storage, table, _ = build_storage()
    table.put_item.side_effect = ClientError(
        {"Error": {"Code": "AccessDeniedException", "Message": "sensitive details"}},
        "PutItem",
    )

    with pytest.raises(StorageError, match="could not be saved") as raised:
        storage.save_finding(sample_finding())

    assert "sensitive details" not in str(raised.value)


@pytest.mark.parametrize("limit", [0, -1, True])
def test_invalid_list_limit_is_rejected(limit: int) -> None:
    storage, _, _ = build_storage()

    with pytest.raises(ValueError, match="positive integer"):
        storage.list_findings(limit=limit)
