"""Tests for audit-oriented compliance report generation."""

from __future__ import annotations

import csv
import io
import json
from datetime import UTC, datetime

from cloud_security_governance import ComplianceEngine, RiskCalculator
from cloud_security_governance.models import (
    CloudProvider,
    Finding,
    RemediationAction,
    RemediationStatus,
    Resource,
    Severity,
)
from cloud_security_governance.reports import ComplianceReportGenerator

NOW = datetime(2026, 9, 24, 12, 0, tzinfo=UTC)


def findings() -> list[Finding]:
    return [
        Finding(
            rule_id="aws.iam.root.access-key",
            resource=Resource(
                resource_id="arn:aws:iam::123456789012:root",
                provider=CloudProvider.AWS,
                account_id="123456789012",
                resource_type="AWS::IAM::RootAccount",
                name="root",
            ),
            title="Root access key <script>alert(1)</script>",
            description="The root account has an active access key.",
            severity=Severity.CRITICAL,
            detected_at=NOW,
        ),
        Finding(
            rule_id="azure.policy.non-compliant-resource",
            resource=Resource(
                resource_id=(
                    "/subscriptions/11111111-1111-4111-8111-111111111111/"
                    "resourceGroups/test/providers/Microsoft.Compute/virtualMachines/web01"
                ),
                provider=CloudProvider.AZURE,
                account_id="11111111-1111-4111-8111-111111111111",
                resource_type="Microsoft.Compute/virtualMachines",
                name="web01",
            ),
            title="Policy violation",
            description="The virtual machine violates the security baseline.",
            severity=Severity.HIGH,
            detected_at=NOW,
        ),
        Finding(
            rule_id="azure.storage.encryption.infrastructure-enabled",
            resource=Resource(
                resource_id=(
                    "/subscriptions/11111111-1111-4111-8111-111111111111/"
                    "resourceGroups/test/providers/Microsoft.Storage/storageAccounts/audit"
                ),
                provider=CloudProvider.AZURE,
                account_id="11111111-1111-4111-8111-111111111111",
                resource_type="Microsoft.Storage/storageAccounts",
                name="audit",
            ),
            title="Infrastructure encryption missing",
            description="Secondary encryption is not enabled.",
            severity=Severity.MEDIUM,
            detected_at=NOW,
        ),
    ]


def report_inputs():
    scanner_findings = findings()
    compliance = ComplianceEngine(clock=lambda: NOW).evaluate(scanner_findings)
    risk = RiskCalculator().calculate(scanner_findings)
    remediation = RemediationAction(
        finding_id=scanner_findings[0].finding_id,
        action_type="remove-root-key",
        description="Remove the root access key after validating dependencies.",
        status=RemediationStatus.IN_PROGRESS,
        created_at=NOW,
        started_at=NOW,
    )
    return scanner_findings, compliance, risk, remediation


def test_json_report_contains_all_required_audit_sections() -> None:
    scanner_findings, compliance, risk, remediation = report_inputs()

    rendered = ComplianceReportGenerator().generate_json(
        compliance, risk, remediation_history=[remediation]
    )
    payload = json.loads(rendered)

    assert "executive_summary" in payload
    assert payload["overall_compliance"]["rules_evaluated"] == 20
    assert payload["risk_score"]["overall_risk_score"] == 40
    assert len(payload["critical_findings"]) == 1
    assert len(payload["high_findings"]) == 1
    assert len(payload["medium_findings"]) == 1
    assert len(payload["aws_findings"]) == 1
    assert len(payload["azure_findings"]) == 2
    assert payload["remediation_status"]["in_progress"] == 1
    assert payload["remediation_status"]["not_started"] == 2
    assert {row["finding_id"] for row in payload["all_findings"]} == {
        str(item.finding_id) for item in scanner_findings
    }


def test_csv_report_is_parseable_and_contains_summary_and_findings() -> None:
    _, compliance, risk, remediation = report_inputs()

    rendered = ComplianceReportGenerator().generate_csv(
        compliance, risk, remediation_history=[remediation]
    )
    rows = list(csv.reader(io.StringIO(rendered)))

    assert rows[0][0] == "Executive Summary"
    assert rows[1][0] == "Overall Compliance"
    assert rows[2] == ["Overall Risk Score", "40"]
    assert rows[3:8] == [
        ["Critical Findings", "1"],
        ["High Findings", "1"],
        ["Medium Findings", "1"],
        ["AWS Findings", "1"],
        ["Azure Findings", "2"],
    ]
    assert rows[10][0:3] == ["finding_id", "cloud", "account_or_subscription"]
    assert len(rows) == 14


def test_html_report_is_readable_and_escapes_finding_content() -> None:
    _, compliance, risk, remediation = report_inputs()

    rendered = ComplianceReportGenerator().generate_html(
        compliance, risk, remediation_history=[remediation]
    )

    assert "Cloud Security Compliance Report" in rendered
    assert "Executive Summary" in rendered
    assert "Overall compliance" in rendered
    assert "Overall risk score" in rendered
    assert "Remediation Status" in rendered
    assert "<table>" in rendered
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in rendered
    assert "<script>alert(1)</script>" not in rendered


def test_generate_returns_all_three_formats_consistently() -> None:
    _, compliance, risk, remediation = report_inputs()

    reports = ComplianceReportGenerator().generate(
        compliance, risk, remediation_history=[remediation]
    )

    assert json.loads(reports.json_report)["risk_score"]["overall_risk_score"] == 40
    assert "Overall Risk Score,40" in reports.csv_report
    assert "40/100" in reports.html_report
