"""Safe offline portfolio demonstration using real application services and mocked clouds."""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path
from typing import Any, ClassVar
from uuid import UUID

from cloud_security_governance.base_scanner import BaseScanner
from cloud_security_governance.compliance_engine import ComplianceEngine
from cloud_security_governance.models import (
    CloudAccount,
    CloudProvider,
    Finding,
    FindingStatus,
    MultiCloudScanResult,
    RemediationAction,
    Resource,
    ScanResult,
    Severity,
)
from cloud_security_governance.notifications import WebhookNotifier
from cloud_security_governance.orchestrator import ScannerOrchestrator
from cloud_security_governance.remediation import (
    ApprovalService,
    RemediationEngine,
    StorageAuditSink,
)
from cloud_security_governance.remediation.azure import REMOVE_RBAC_ASSIGNMENT
from cloud_security_governance.remediation.core import JsonObject, RemediationExecutor
from cloud_security_governance.reports import ComplianceReportGenerator
from cloud_security_governance.risk import RiskCalculator
from cloud_security_governance.storage import FindingStorage
from cloud_security_governance.workflow import ComplianceWorkflowService


class DemoScanner(BaseScanner):
    def __init__(
        self, provider: CloudProvider, account: CloudAccount, findings: list[Finding]
    ) -> None:
        self.provider = provider
        self.account = account
        self.findings = findings

    def scan(self) -> ScanResult:
        now = datetime.now(UTC)
        return ScanResult(
            account=self.account,
            started_at=now,
            completed_at=now,
            resources_scanned=max(len(self.findings), 1),
            findings=list(self.findings),
        )


class MemoryStorage(FindingStorage):
    def __init__(self) -> None:
        self.findings: dict[UUID, Finding] = {}
        self.scans: dict[UUID, ScanResult | MultiCloudScanResult] = {}
        self.remediations: list[RemediationAction] = []

    def save_finding(self, finding: Finding) -> None:
        self.findings[finding.finding_id] = finding

    def get_finding(self, finding_id: UUID | str) -> Finding | None:
        return self.findings.get(UUID(str(finding_id)))

    def list_findings(
        self,
        *,
        provider: CloudProvider | None = None,
        status: FindingStatus | None = None,
        limit: int | None = None,
    ) -> list[Finding]:
        values = [
            finding
            for finding in self.findings.values()
            if (provider is None or finding.resource.provider is provider)
            and (status is None or finding.status is status)
        ]
        return values[:limit]

    def update_finding_status(self, finding_id: UUID | str, status: FindingStatus) -> Finding:
        finding = self.findings[UUID(str(finding_id))].model_copy(
            update={"status": status, "updated_at": datetime.now(UTC)}
        )
        self.findings[finding.finding_id] = finding
        return finding

    def save_scan_metadata(self, scan: ScanResult | MultiCloudScanResult) -> None:
        self.scans[scan.scan_id] = scan

    def get_scan_metadata(self, scan_id: UUID | str) -> ScanResult | MultiCloudScanResult | None:
        return self.scans.get(UUID(str(scan_id)))

    def save_remediation_history(self, action: RemediationAction) -> None:
        self.remediations.append(action)


class DemoRBACRemediation(RemediationExecutor):
    provider: ClassVar[CloudProvider] = CloudProvider.AZURE
    action = REMOVE_RBAC_ASSIGNMENT

    def __init__(self, scanner: DemoScanner) -> None:
        self.scanner = scanner

    def review(self, finding: Finding, parameters: JsonObject) -> JsonObject:
        return {"role_assignment_id": parameters["role_assignment_id"], "exists": True}

    def execute(self, finding: Finding, parameters: JsonObject) -> JsonObject:
        self.scanner.findings = [item for item in self.scanner.findings if item != finding]
        return {"role_assignment_id": parameters["role_assignment_id"], "exists": False}

    def verify(self, finding: Finding, parameters: JsonObject) -> tuple[bool, JsonObject]:
        exists = finding in self.scanner.findings
        return not exists, {
            "role_assignment_id": parameters["role_assignment_id"],
            "exists": exists,
        }


class DemoResponse:
    status = 204

    def close(self) -> None:
        return None


def finding(
    *, provider: CloudProvider, account_id: str, rule_id: str, severity: Severity, resource_id: str
) -> Finding:
    return Finding(
        rule_id=rule_id,
        resource=Resource(
            resource_id=resource_id,
            provider=provider,
            account_id=account_id,
            resource_type="demo/security-resource",
            name=resource_id.rsplit("/", 1)[-1],
        ),
        title=f"Demonstration violation: {rule_id}",
        description="Sanitized intentionally vulnerable training resource.",
        severity=severity,
        remediation_available=True,
    )


def main() -> None:
    rules_path = Path(__file__).resolve().parents[1] / "config" / "rules.yaml"
    aws_id = "123456789012"
    azure_id = "11111111-1111-1111-1111-111111111111"
    aws = DemoScanner(
        CloudProvider.AWS,
        CloudAccount(account_id=aws_id, provider=CloudProvider.AWS, display_name="Demo AWS"),
        [
            finding(
                provider=CloudProvider.AWS,
                account_id=aws_id,
                rule_id="aws.iam.access-key.stale",
                severity=Severity.HIGH,
                resource_id="arn:aws:iam::123456789012:user/demo/access-key/DEMOONLY",
            )
        ],
    )
    assignment_id = (
        f"/subscriptions/{azure_id}/providers/Microsoft.Authorization/roleAssignments/demo"
    )
    azure_finding = finding(
        provider=CloudProvider.AZURE,
        account_id=azure_id,
        rule_id="azure.rbac.owner-assignment",
        severity=Severity.CRITICAL,
        resource_id=assignment_id,
    )
    azure = DemoScanner(
        CloudProvider.AZURE,
        CloudAccount(
            account_id=azure_id,
            provider=CloudProvider.AZURE,
            display_name="Demo Azure",
            tenant_id="22222222-2222-2222-2222-222222222222",
        ),
        [azure_finding],
    )
    storage = MemoryStorage()
    sent_alerts: list[str] = []

    def send(request: Any, *, timeout: float) -> DemoResponse:
        del timeout
        sent_alerts.append(request.full_url)
        return DemoResponse()

    workflow = ComplianceWorkflowService(
        scanner=ScannerOrchestrator([aws, azure]),
        compliance_engine=ComplianceEngine(rules_path=rules_path),
        risk_calculator=RiskCalculator(),
        storage=storage,
        report_generator=ComplianceReportGenerator(),
        notifiers=[
            WebhookNotifier(
                "https://alerts.invalid/security",
                alert_severities=(Severity.CRITICAL, Severity.HIGH),
                sender=send,
            )
        ],
    )
    before = workflow.run()
    output = Path("demo-output")
    output.mkdir(exist_ok=True)
    (output / "before.json").write_text(before.reports.json_report, encoding="utf-8")
    (output / "before.csv").write_text(before.reports.csv_report, encoding="utf-8")
    (output / "before.html").write_text(before.reports.html_report, encoding="utf-8")
    initial_alerts = len(sent_alerts)

    approvals = ApprovalService()
    remediation = RemediationEngine(
        approvals,
        [DemoRBACRemediation(azure)],
        StorageAuditSink(storage),
    )
    parameters = {"role_assignment_id": assignment_id}
    review = remediation.review_and_request(
        azure_finding, REMOVE_RBAC_ASSIGNMENT, parameters, "demo-requester"
    )
    approvals.approve(review.approval.approval_id, "demo-reviewer", "Interview demo approval")
    result = remediation.remediate(
        azure_finding,
        REMOVE_RBAC_ASSIGNMENT,
        "demo-operator",
        parameters,
        approval_id=review.approval.approval_id,
    )
    after = workflow.run(remediation_history=storage.remediations)
    (output / "after.json").write_text(after.reports.json_report, encoding="utf-8")
    (output / "after.csv").write_text(after.reports.csv_report, encoding="utf-8")
    (output / "after.html").write_text(after.reports.html_report, encoding="utf-8")

    print("AWS scan findings:", len(before.scan.results[0].findings))
    print("Azure scan findings:", len(before.scan.results[1].findings))
    print("Normalized findings:", len(before.scan.findings))
    print(
        "Initial compliance:",
        f"{before.compliance.compliant_rules}/{before.compliance.rules_evaluated}",
    )
    print("Initial risk:", before.risk.overall_risk_score)
    print("Reports: JSON, CSV, HTML")
    print("Initial alerts sent:", initial_alerts)
    print("Approval:", review.approval.approval_id)
    print("Remediation:", result.outcome.value, "verified=", result.verified)
    print("Improved findings:", len(after.scan.findings))
    print(
        "Improved compliance:",
        f"{after.compliance.compliant_rules}/{after.compliance.rules_evaluated}",
    )
    print("Improved risk:", after.risk.overall_risk_score)
    print("Artifacts:", output.resolve())


if __name__ == "__main__":
    main()
