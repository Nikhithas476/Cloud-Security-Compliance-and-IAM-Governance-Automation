from types import SimpleNamespace
from unittest.mock import Mock
from uuid import uuid4

from azure.core.exceptions import ResourceNotFoundError

from cloud_security_governance.models import FindingStatus
from cloud_security_governance.remediation import ApprovalService
from cloud_security_governance.storage import AzureBlobStorage
from tests.test_dynamodb_storage import sample_finding, sample_scan


class BlobContainer:
    def __init__(self) -> None:
        self.records: dict[str, bytes] = {}

    def upload_blob(self, *, name: str, data: bytes, overwrite: bool) -> None:
        assert overwrite is True
        self.records[name] = data

    def download_blob(self, name: str):
        if name not in self.records:
            raise ResourceNotFoundError("missing")
        return SimpleNamespace(readall=lambda: self.records[name])

    def list_blobs(self, *, name_starts_with: str):
        return [
            SimpleNamespace(name=name) for name in self.records if name.startswith(name_starts_with)
        ]


def build_storage() -> tuple[AzureBlobStorage, BlobContainer]:
    container = BlobContainer()
    service = Mock()
    service.get_container_client.return_value = container
    storage = AzureBlobStorage(
        account_url="https://governance.blob.core.windows.net",
        credential_factory=Mock(return_value=object()),
        client_factory=Mock(return_value=service),
    )
    return storage, container


def test_azure_blob_persists_workflow_records() -> None:
    storage, _ = build_storage()
    finding = sample_finding()
    storage.save_finding(finding)
    assert storage.get_finding(finding.finding_id) == finding
    assert storage.list_findings() == [finding]
    assert (
        storage.update_finding_status(finding.finding_id, FindingStatus.RESOLVED).status
        is FindingStatus.RESOLVED
    )

    scan = sample_scan(finding)
    storage.save_scan_metadata(scan)
    assert storage.get_scan_metadata(scan.scan_id) == scan
    reports = {"json": "{}", "csv": "header", "html": "<html></html>"}
    storage.save_reports(scan.scan_id, reports)
    assert storage.get_reports(scan.scan_id) == reports

    approval = ApprovalService().request(finding.finding_id, "aws.test.action", {}, "operator")
    storage.save_approval(approval)
    assert storage.get_approval(approval.approval_id) == approval


def test_azure_blob_missing_records_return_none() -> None:
    storage, _ = build_storage()
    assert storage.get_finding(uuid4()) is None
    assert storage.get_scan_metadata(uuid4()) is None
    assert storage.get_reports(uuid4()) is None
    assert storage.get_approval(uuid4()) is None
