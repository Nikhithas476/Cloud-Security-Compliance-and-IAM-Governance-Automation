"""Single-table DynamoDB persistence for findings, scans, and remediation history."""

from __future__ import annotations

import json
import os
from collections.abc import Callable
from datetime import UTC, datetime
from decimal import Decimal
from typing import Any
from uuid import UUID

import boto3
from botocore.exceptions import BotoCoreError, ClientError

from cloud_security_governance.exceptions import (
    RecordNotFoundError,
    StorageError,
)
from cloud_security_governance.models import (
    CloudProvider,
    Finding,
    FindingStatus,
    MultiCloudScanResult,
    RemediationAction,
    ScanResult,
)
from cloud_security_governance.storage.base import FindingStorage

FINDINGS_INDEX = "GSI1"


def _utc_now() -> datetime:
    return datetime.now(UTC)


class DynamoDBStorage(FindingStorage):
    """Persist workflow records without accepting or storing AWS credentials."""

    def __init__(
        self,
        *,
        table_name: str | None = None,
        region: str | None = None,
        resource_factory: Callable[..., Any] = boto3.resource,
        clock: Callable[[], datetime] = _utc_now,
    ) -> None:
        resolved_table = table_name or os.getenv("DYNAMODB_TABLE_NAME")
        if resolved_table is None or not resolved_table.strip():
            raise StorageError("DYNAMODB_TABLE_NAME is required")
        self.table_name = resolved_table.strip()
        self.region = region or os.getenv("AWS_REGION") or os.getenv("AWS_DEFAULT_REGION")
        self._clock = clock
        options = {"region_name": self.region} if self.region else {}
        try:
            self._dynamodb = resource_factory("dynamodb", **options)
            self._table = self._dynamodb.Table(self.table_name)
        except (BotoCoreError, ClientError, OSError) as exc:
            raise StorageError("DynamoDB storage could not be initialized") from exc

    def save_finding(self, finding: Finding) -> None:
        normalized = Finding.model_validate(finding)
        item = {
            "PK": f"FINDING#{normalized.finding_id}",
            "SK": "METADATA",
            "GSI1PK": "FINDINGS",
            "GSI1SK": f"{normalized.detected_at.isoformat()}#{normalized.finding_id}",
            "record_type": "finding",
            "provider": normalized.resource.provider.value,
            "status": normalized.status.value,
            "severity": normalized.severity.value,
            "payload": self._serialize(normalized),
        }
        self._put(item, "finding")

    def get_finding(self, finding_id: UUID | str) -> Finding | None:
        identifier = self._uuid(finding_id, "finding ID")
        item = self._get(f"FINDING#{identifier}", "METADATA")
        return None if item is None else Finding.model_validate(item.get("payload"))

    def list_findings(
        self,
        *,
        provider: CloudProvider | None = None,
        status: FindingStatus | None = None,
        limit: int | None = None,
    ) -> list[Finding]:
        if limit is not None and (isinstance(limit, bool) or limit < 1):
            raise ValueError("limit must be a positive integer")
        values: dict[str, Any] = {":finding_partition": "FINDINGS"}
        filters: list[str] = []
        if provider is not None:
            values[":provider"] = CloudProvider(provider).value
            filters.append("provider = :provider")
        if status is not None:
            values[":status"] = FindingStatus(status).value
            filters.append("#status = :status")
        options: dict[str, Any] = {
            "IndexName": FINDINGS_INDEX,
            "KeyConditionExpression": "GSI1PK = :finding_partition",
            "ExpressionAttributeValues": values,
            "ScanIndexForward": False,
        }
        if filters:
            options["FilterExpression"] = " AND ".join(filters)
        if status is not None:
            options["ExpressionAttributeNames"] = {"#status": "status"}

        findings: list[Finding] = []
        try:
            while True:
                response = self._table.query(**options)
                items = response.get("Items", [])
                if not isinstance(items, list):
                    raise StorageError("DynamoDB returned invalid finding results")
                for item in items:
                    findings.append(Finding.model_validate(item.get("payload")))
                    if limit is not None and len(findings) >= limit:
                        return findings
                last_key = response.get("LastEvaluatedKey")
                if not last_key:
                    break
                options["ExclusiveStartKey"] = last_key
        except (BotoCoreError, ClientError, OSError) as exc:
            raise StorageError("DynamoDB findings could not be listed") from exc
        return findings

    def update_finding_status(
        self,
        finding_id: UUID | str,
        status: FindingStatus,
    ) -> Finding:
        identifier = self._uuid(finding_id, "finding ID")
        normalized_status = FindingStatus(status)
        updated_at = self._normalize_time(self._clock())
        try:
            response = self._table.update_item(
                Key={"PK": f"FINDING#{identifier}", "SK": "METADATA"},
                UpdateExpression=(
                    "SET #payload.#status = :status, #payload.#updated_at = :updated_at, "
                    "#status = :status"
                ),
                ConditionExpression="attribute_exists(PK)",
                ExpressionAttributeNames={
                    "#payload": "payload",
                    "#status": "status",
                    "#updated_at": "updated_at",
                },
                ExpressionAttributeValues={
                    ":status": normalized_status.value,
                    ":updated_at": updated_at.isoformat(),
                },
                ReturnValues="ALL_NEW",
            )
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code")
            if code == "ConditionalCheckFailedException":
                raise RecordNotFoundError(f"Finding was not found: {identifier}") from exc
            raise StorageError("DynamoDB finding status could not be updated") from exc
        except (BotoCoreError, OSError) as exc:
            raise StorageError("DynamoDB finding status could not be updated") from exc
        attributes = response.get("Attributes")
        if not isinstance(attributes, dict):
            raise StorageError("DynamoDB returned no updated finding")
        return Finding.model_validate(attributes.get("payload"))

    def save_scan_metadata(self, scan: ScanResult | MultiCloudScanResult) -> None:
        if isinstance(scan, MultiCloudScanResult):
            normalized: ScanResult | MultiCloudScanResult = MultiCloudScanResult.model_validate(
                scan
            )
            model_type = "multi_cloud"
        else:
            normalized = ScanResult.model_validate(scan)
            model_type = "cloud"
        item = {
            "PK": f"SCAN#{normalized.scan_id}",
            "SK": "METADATA",
            "record_type": "scan",
            "model_type": model_type,
            "payload": self._serialize(normalized),
        }
        self._put(item, "scan metadata")

    def get_scan_metadata(self, scan_id: UUID | str) -> ScanResult | MultiCloudScanResult | None:
        identifier = self._uuid(scan_id, "scan ID")
        item = self._get(f"SCAN#{identifier}", "METADATA")
        if item is None:
            return None
        payload = item.get("payload")
        if item.get("model_type") == "multi_cloud":
            return MultiCloudScanResult.model_validate(payload)
        if item.get("model_type") == "cloud":
            return ScanResult.model_validate(payload)
        raise StorageError("DynamoDB returned an unknown scan metadata type")

    def save_remediation_history(self, action: RemediationAction) -> None:
        normalized = RemediationAction.model_validate(action)
        item = {
            "PK": f"FINDING#{normalized.finding_id}",
            "SK": f"REMEDIATION#{normalized.created_at.isoformat()}#{normalized.action_id}",
            "record_type": "remediation",
            "payload": self._serialize(normalized),
        }
        self._put(item, "remediation history")

    def save_approval(self, approval: object) -> None:
        from cloud_security_governance.remediation import ApprovalRequest

        normalized = ApprovalRequest.model_validate(approval)
        self._put(
            {
                "PK": f"APPROVAL#{normalized.approval_id}",
                "SK": "METADATA",
                "record_type": "approval",
                "payload": self._serialize(normalized),
            },
            "approval",
        )

    def get_approval(self, approval_id: UUID | str) -> object | None:
        from cloud_security_governance.remediation import ApprovalRequest

        identifier = self._uuid(approval_id, "approval ID")
        item = self._get(f"APPROVAL#{identifier}", "METADATA")
        return None if item is None else ApprovalRequest.model_validate(item.get("payload"))

    def save_reports(self, scan_id: UUID | str, reports: dict[str, str]) -> None:
        identifier = self._uuid(scan_id, "scan ID")
        self._put(
            {
                "PK": f"SCAN#{identifier}",
                "SK": "REPORTS",
                "record_type": "reports",
                "payload": dict(reports),
            },
            "reports",
        )

    def get_reports(self, scan_id: UUID | str) -> dict[str, str] | None:
        identifier = self._uuid(scan_id, "scan ID")
        item = self._get(f"SCAN#{identifier}", "REPORTS")
        if item is None:
            return None
        payload = item.get("payload")
        if not isinstance(payload, dict) or not all(
            isinstance(key, str) and isinstance(value, str) for key, value in payload.items()
        ):
            raise StorageError("DynamoDB returned invalid report data")
        return payload

    def _put(self, item: dict[str, Any], context: str) -> None:
        try:
            self._table.put_item(Item=item)
        except (BotoCoreError, ClientError, OSError) as exc:
            raise StorageError(f"DynamoDB {context} could not be saved") from exc

    def _get(self, partition_key: str, sort_key: str) -> dict[str, Any] | None:
        try:
            response = self._table.get_item(
                Key={"PK": partition_key, "SK": sort_key},
                ConsistentRead=True,
            )
        except (BotoCoreError, ClientError, OSError) as exc:
            raise StorageError("DynamoDB record could not be retrieved") from exc
        item = response.get("Item")
        if item is not None and not isinstance(item, dict):
            raise StorageError("DynamoDB returned an invalid record")
        return item

    @staticmethod
    def _serialize(model: Any) -> dict[str, Any]:
        return json.loads(model.model_dump_json(), parse_float=Decimal)

    @staticmethod
    def _uuid(value: UUID | str, context: str) -> UUID:
        try:
            return value if isinstance(value, UUID) else UUID(str(value))
        except ValueError as exc:
            raise ValueError(f"{context} must be a valid UUID") from exc

    @staticmethod
    def _normalize_time(value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise StorageError("Storage timestamps must include timezone information")
        return value.astimezone(UTC)
