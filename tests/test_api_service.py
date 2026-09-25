from types import SimpleNamespace
from unittest.mock import Mock
from uuid import uuid4

from cloud_security_governance.api_service import GovernanceAPIService
from cloud_security_governance.models import CloudProvider, FindingStatus


def test_api_service_delegates_workflow_storage_reports_and_remediation() -> None:
    workflow = Mock()
    storage = Mock()
    remediation = Mock()
    scan_id = uuid4()
    reports = SimpleNamespace(json_report="{}", csv_report="csv", html_report="html")
    workflow.run.return_value = SimpleNamespace(
        scan=SimpleNamespace(scan_id=scan_id), reports=reports
    )
    storage.get_reports.return_value = None
    service = GovernanceAPIService(workflow, storage, remediation)

    assert service.start_scan() is workflow.run.return_value
    assert service.get_reports(scan_id) == {"json": "{}", "csv": "csv", "html": "html"}
    assert service.get_reports(uuid4()) is None
    storage.save_reports.assert_called_once_with(
        scan_id, {"json": "{}", "csv": "csv", "html": "html"}
    )

    service.get_scan(scan_id)
    service.list_findings(provider=CloudProvider.AWS, status=FindingStatus.OPEN, limit=5)
    storage.get_scan_metadata.assert_called_once_with(scan_id)
    storage.list_findings.assert_called_once_with(
        provider=CloudProvider.AWS, status=FindingStatus.OPEN, limit=5
    )


def test_api_service_returns_none_for_missing_remediation_finding() -> None:
    storage = Mock()
    storage.get_finding.return_value = None
    remediation = Mock()
    service = GovernanceAPIService(Mock(), storage, remediation)
    assert (
        service.remediate(
            uuid4(),
            action="aws.test.action",
            actor="operator",
            parameters={},
            approval_id=None,
            dry_run=True,
        )
        is None
    )
    remediation.remediate.assert_not_called()


def test_api_service_executes_remediation_for_existing_finding() -> None:
    storage = Mock()
    finding = Mock()
    storage.get_finding.return_value = finding
    remediation = Mock()
    remediation.remediate.return_value = Mock()
    service = GovernanceAPIService(Mock(), storage, remediation)
    finding_id = uuid4()
    result = service.remediate(
        finding_id,
        action="aws.test.action",
        actor="operator",
        parameters={"target": "x"},
        approval_id=None,
        dry_run=True,
    )
    assert result is remediation.remediate.return_value
    remediation.remediate.assert_called_once_with(
        finding,
        "aws.test.action",
        "operator",
        {"target": "x"},
        approval_id=None,
        dry_run=True,
    )
