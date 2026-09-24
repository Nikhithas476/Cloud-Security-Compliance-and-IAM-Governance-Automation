"""Integration tests for the complete compliance workflow with mocked boundaries."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from unittest.mock import MagicMock
from uuid import UUID

from cloud_security_governance import (
    BaseScanner,
    ComplianceEngine,
    RiskCalculator,
    ScannerOrchestrator,
)
from cloud_security_governance.models import (
    CloudAccount,
    CloudProvider,
    Finding,
    RemediationAction,
    Resource,
    ScanResult,
    Severity,
)
from cloud_security_governance.notifications import WebhookNotifier
from cloud_security_governance.reports import ComplianceReportGenerator
from cloud_security_governance.storage import DynamoDBStorage
from cloud_security_governance.workflow import ComplianceWorkflowService

NOW = datetime(2026, 9, 24, 12, 0, tzinfo=UTC)
AWS_ACCOUNT_ID = "123456789012"
AZURE_SUBSCRIPTION_ID = "11111111-1111-4111-8111-111111111111"
AZURE_TENANT_ID = UUID("22222222-2222-4222-8222-222222222222")


class MockCloudAPIScanner(BaseScanner):
    """Complete scanner whose cloud API call is explicitly mocked."""

    def __init__(self, provider: CloudProvider, cloud_api: MagicMock) -> None:
        self.provider = provider
        self.cloud_api = cloud_api

    def scan(self) -> ScanResult:
        return self.cloud_api.run_read_only_scan()


def aws_result() -> ScanResult:
    finding = Finding(
        rule_id="aws.iam.root.access-key",
        resource=Resource(
            resource_id=f"arn:aws:iam::{AWS_ACCOUNT_ID}:root",
            provider=CloudProvider.AWS,
            account_id=AWS_ACCOUNT_ID,
            resource_type="AWS::IAM::RootAccount",
            name="root",
        ),
        title="Root access key exists",
        description="The root account has an active access key.",
        severity=Severity.CRITICAL,
        detected_at=NOW,
    )
    return ScanResult(
        account=CloudAccount(
            account_id=AWS_ACCOUNT_ID,
            provider=CloudProvider.AWS,
            display_name="AWS audit account",
        ),
        started_at=NOW,
        completed_at=NOW,
        resources_scanned=1,
        findings=[finding],
    )


def azure_result() -> ScanResult:
    finding = Finding(
        rule_id="azure.policy.non-compliant-resource",
        resource=Resource(
            resource_id=(
                f"/subscriptions/{AZURE_SUBSCRIPTION_ID}/resourceGroups/test/"
                "providers/Microsoft.Compute/virtualMachines/web01"
            ),
            provider=CloudProvider.AZURE,
            account_id=AZURE_SUBSCRIPTION_ID,
            resource_type="Microsoft.Compute/virtualMachines",
            name="web01",
        ),
        title="Azure Policy violation",
        description="The virtual machine violates the security baseline.",
        severity=Severity.HIGH,
        detected_at=NOW,
    )
    return ScanResult(
        account=CloudAccount(
            account_id=AZURE_SUBSCRIPTION_ID,
            provider=CloudProvider.AZURE,
            display_name="Azure audit subscription",
            tenant_id=AZURE_TENANT_ID,
        ),
        started_at=NOW,
        completed_at=NOW,
        resources_scanned=1,
        findings=[finding],
    )


def test_complete_workflow_connects_scanning_storage_reports_and_alerting() -> None:
    aws_scan = aws_result()
    azure_scan = azure_result()
    aws_api = MagicMock()
    aws_api.run_read_only_scan.return_value = aws_scan
    azure_api = MagicMock()
    azure_api.run_read_only_scan.return_value = azure_scan
    scanner = ScannerOrchestrator(
        [
            MockCloudAPIScanner(CloudProvider.AWS, aws_api),
            MockCloudAPIScanner(CloudProvider.AZURE, azure_api),
        ],
        clock=MagicMock(side_effect=[NOW, NOW]),
    )

    table = MagicMock()
    dynamodb = MagicMock()
    dynamodb.Table.return_value = table
    storage = DynamoDBStorage(
        table_name="security-governance",
        region="us-east-1",
        resource_factory=MagicMock(return_value=dynamodb),
        clock=MagicMock(return_value=NOW),
    )
    webhook_response = MagicMock(status=204)
    webhook_sender = MagicMock(return_value=webhook_response)
    notifier = WebhookNotifier(
        "https://alerts.example.test/security",
        sender=webhook_sender,
    )
    service = ComplianceWorkflowService(
        scanner=scanner,
        compliance_engine=ComplianceEngine(clock=MagicMock(return_value=NOW)),
        risk_calculator=RiskCalculator(),
        storage=storage,
        report_generator=ComplianceReportGenerator(),
        notifiers=[notifier],
    )
    remediation = RemediationAction(
        finding_id=aws_scan.findings[0].finding_id,
        action_type="security-review",
        description="Review the critical finding with the cloud security team.",
        created_at=NOW,
    )

    result = service.run(remediation_history=[remediation])

    aws_api.run_read_only_scan.assert_called_once_with()
    azure_api.run_read_only_scan.assert_called_once_with()
    assert result.scan.findings_count == 2
    assert result.compliance.non_compliant_rules == 2
    assert result.risk.overall_risk_score == 35
    assert result.risk.aws_risk_score == 25
    assert result.risk.azure_risk_score == 10
    assert result.alerts_sent == 1
    assert result.alert_errors == ()
    assert table.put_item.call_count == 4  # two findings, aggregate scan, remediation history
    assert "Cloud Security Compliance Report" in result.reports.html_report
    assert json.loads(result.reports.json_report)["overall_compliance"]["non_compliant_rules"] == 2
    webhook_sender.assert_called_once()
    alert_payload = json.loads(webhook_sender.call_args.args[0].data.decode("utf-8"))
    assert alert_payload["severity"] == "critical"
    assert set(alert_payload) == {
        "cloud",
        "account_or_subscription",
        "resource",
        "rule",
        "severity",
        "description",
        "finding_id",
    }
