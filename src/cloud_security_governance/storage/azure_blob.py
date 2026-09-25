"""Azure Blob persistence using managed identity or DefaultAzureCredential."""

from __future__ import annotations

import json
import os
from collections.abc import Callable
from datetime import UTC, datetime
from typing import Any
from uuid import UUID

from azure.core.exceptions import AzureError, ResourceNotFoundError
from azure.identity import DefaultAzureCredential
from azure.storage.blob import BlobServiceClient

from cloud_security_governance.exceptions import RecordNotFoundError, StorageError
from cloud_security_governance.models import (
    CloudProvider,
    Finding,
    FindingStatus,
    MultiCloudScanResult,
    RemediationAction,
    ScanResult,
)
from cloud_security_governance.storage.base import FindingStorage


class AzureBlobStorage(FindingStorage):
    """Persist governance JSON documents in a private Azure Blob container."""

    def __init__(
        self,
        *,
        account_url: str | None = None,
        container_name: str | None = None,
        credential_factory: Callable[[], Any] = DefaultAzureCredential,
        client_factory: Callable[..., Any] = BlobServiceClient,
    ) -> None:
        self.account_url = account_url or os.getenv("AZURE_STORAGE_ACCOUNT_URL", "")
        self.container_name = container_name or os.getenv(
            "AZURE_STORAGE_CONTAINER", "governance-records"
        )
        if not self.account_url.startswith("https://"):
            raise StorageError("AZURE_STORAGE_ACCOUNT_URL must be an HTTPS URL")
        if not self.container_name or not self.container_name.replace("-", "").isalnum():
            raise StorageError("AZURE_STORAGE_CONTAINER is invalid")
        try:
            service = client_factory(self.account_url, credential=credential_factory())
            self._container = service.get_container_client(self.container_name)
        except (AzureError, OSError) as exc:
            raise StorageError("Azure Blob storage could not be initialized") from exc

    def save_finding(self, finding: Finding) -> None:
        normalized = Finding.model_validate(finding)
        self._write(f"findings/{normalized.finding_id}.json", normalized.model_dump_json())

    def get_finding(self, finding_id: UUID | str) -> Finding | None:
        payload = self._read(f"findings/{self._uuid(finding_id, 'finding ID')}.json")
        return None if payload is None else Finding.model_validate_json(payload)

    def list_findings(
        self,
        *,
        provider: CloudProvider | None = None,
        status: FindingStatus | None = None,
        limit: int | None = None,
    ) -> list[Finding]:
        if limit is not None and (isinstance(limit, bool) or limit < 1):
            raise ValueError("limit must be a positive integer")
        findings: list[Finding] = []
        try:
            blobs = self._container.list_blobs(name_starts_with="findings/")
            for blob in blobs:
                payload = self._read(str(blob.name))
                if payload is None:
                    continue
                finding = Finding.model_validate_json(payload)
                if provider is not None and finding.resource.provider is not provider:
                    continue
                if status is not None and finding.status is not status:
                    continue
                findings.append(finding)
                if limit is not None and len(findings) >= limit:
                    break
        except (AzureError, OSError) as exc:
            raise StorageError("Azure Blob findings could not be listed") from exc
        return sorted(findings, key=lambda item: item.detected_at, reverse=True)

    def update_finding_status(self, finding_id: UUID | str, status: FindingStatus) -> Finding:
        finding = self.get_finding(finding_id)
        if finding is None:
            raise RecordNotFoundError(f"Finding was not found: {finding_id}")
        updated = finding.model_copy(
            update={"status": FindingStatus(status), "updated_at": datetime.now(UTC)}
        )
        self.save_finding(updated)
        return updated

    def save_scan_metadata(self, scan: ScanResult | MultiCloudScanResult) -> None:
        normalized = (
            MultiCloudScanResult.model_validate(scan)
            if isinstance(scan, MultiCloudScanResult)
            else ScanResult.model_validate(scan)
        )
        envelope = {
            "model_type": "multi_cloud"
            if isinstance(normalized, MultiCloudScanResult)
            else "cloud",
            "payload": json.loads(normalized.model_dump_json()),
        }
        self._write(f"scans/{normalized.scan_id}.json", json.dumps(envelope))

    def get_scan_metadata(self, scan_id: UUID | str) -> ScanResult | MultiCloudScanResult | None:
        payload = self._read(f"scans/{self._uuid(scan_id, 'scan ID')}.json")
        if payload is None:
            return None
        envelope = json.loads(payload)
        model = MultiCloudScanResult if envelope.get("model_type") == "multi_cloud" else ScanResult
        return model.model_validate(envelope.get("payload"))

    def save_remediation_history(self, action: RemediationAction) -> None:
        normalized = RemediationAction.model_validate(action)
        name = (
            f"remediations/{normalized.finding_id}/"
            f"{normalized.created_at.isoformat()}-{normalized.action_id}.json"
        )
        self._write(name, normalized.model_dump_json())

    def save_approval(self, approval: object) -> None:
        from cloud_security_governance.remediation import ApprovalRequest

        normalized = ApprovalRequest.model_validate(approval)
        self._write(f"approvals/{normalized.approval_id}.json", normalized.model_dump_json())

    def get_approval(self, approval_id: UUID | str) -> object | None:
        from cloud_security_governance.remediation import ApprovalRequest

        payload = self._read(f"approvals/{self._uuid(approval_id, 'approval ID')}.json")
        return None if payload is None else ApprovalRequest.model_validate_json(payload)

    def save_reports(self, scan_id: UUID | str, reports: dict[str, str]) -> None:
        identifier = self._uuid(scan_id, "scan ID")
        if not all(
            isinstance(key, str) and isinstance(value, str) for key, value in reports.items()
        ):
            raise ValueError("reports must map string formats to string documents")
        self._write(f"reports/{identifier}.json", json.dumps(reports))

    def get_reports(self, scan_id: UUID | str) -> dict[str, str] | None:
        payload = self._read(f"reports/{self._uuid(scan_id, 'scan ID')}.json")
        if payload is None:
            return None
        reports = json.loads(payload)
        if not isinstance(reports, dict) or not all(
            isinstance(key, str) and isinstance(value, str) for key, value in reports.items()
        ):
            raise StorageError("Azure Blob returned invalid report data")
        return reports

    def _write(self, name: str, payload: str) -> None:
        try:
            self._container.upload_blob(name=name, data=payload.encode(), overwrite=True)
        except (AzureError, OSError) as exc:
            raise StorageError("Azure Blob record could not be saved") from exc

    def _read(self, name: str) -> str | None:
        try:
            return self._container.download_blob(name).readall().decode()
        except ResourceNotFoundError:
            return None
        except (AzureError, OSError, UnicodeDecodeError) as exc:
            raise StorageError("Azure Blob record could not be read") from exc

    @staticmethod
    def _uuid(value: UUID | str, context: str) -> UUID:
        try:
            return value if isinstance(value, UUID) else UUID(str(value))
        except ValueError as exc:
            raise ValueError(f"{context} must be a valid UUID") from exc
