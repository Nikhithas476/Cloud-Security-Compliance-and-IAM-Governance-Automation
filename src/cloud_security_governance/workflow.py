"""End-to-end multi-cloud compliance workflow orchestration."""

from __future__ import annotations

from collections.abc import Iterable, Sequence
from dataclasses import dataclass

from cloud_security_governance.compliance_engine import ComplianceEngine
from cloud_security_governance.exceptions import NotificationError
from cloud_security_governance.models import (
    ComplianceReport,
    MultiCloudScanResult,
    RemediationAction,
)
from cloud_security_governance.notifications import NotificationService
from cloud_security_governance.orchestrator import ScannerOrchestrator
from cloud_security_governance.reports import ComplianceReportGenerator, GeneratedReports
from cloud_security_governance.risk import RiskCalculator, RiskScore
from cloud_security_governance.storage import FindingStorage


@dataclass(frozen=True)
class ComplianceWorkflowResult:
    """Outputs and delivery status from one complete compliance workflow."""

    scan: MultiCloudScanResult
    compliance: ComplianceReport
    risk: RiskScore
    reports: GeneratedReports
    alerts_sent: int
    alert_errors: tuple[str, ...]


class ComplianceWorkflowService:
    """Run scanning through alerting without embedding provider-specific logic."""

    def __init__(
        self,
        *,
        scanner: ScannerOrchestrator,
        compliance_engine: ComplianceEngine,
        risk_calculator: RiskCalculator,
        storage: FindingStorage,
        report_generator: ComplianceReportGenerator,
        notifiers: Sequence[NotificationService] = (),
    ) -> None:
        self.scanner = scanner
        self.compliance_engine = compliance_engine
        self.risk_calculator = risk_calculator
        self.storage = storage
        self.report_generator = report_generator
        self.notifiers = tuple(notifiers)

    def run(
        self,
        *,
        remediation_history: Iterable[RemediationAction] = (),
    ) -> ComplianceWorkflowResult:
        """Execute the complete read-only analysis and outbound workflow."""

        remediation_actions = tuple(
            RemediationAction.model_validate(action) for action in remediation_history
        )
        scan = self.scanner.scan()
        compliance = self.compliance_engine.evaluate(scan.findings)
        risk = self.risk_calculator.calculate(scan.findings)

        unique_findings = {finding.finding_id: finding for finding in scan.findings}
        for finding in unique_findings.values():
            self.storage.save_finding(finding)
        self.storage.save_scan_metadata(scan)
        for action in remediation_actions:
            self.storage.save_remediation_history(action)

        reports = self.report_generator.generate(
            compliance,
            risk,
            remediation_history=remediation_actions,
        )
        alerts_sent = 0
        alert_errors: list[str] = []
        for finding in unique_findings.values():
            for notifier in self.notifiers:
                try:
                    alerts_sent += int(notifier.notify(finding))
                except NotificationError as exc:
                    alert_errors.append(str(exc)[:512] or "Notification delivery failed")

        return ComplianceWorkflowResult(
            scan=scan,
            compliance=compliance,
            risk=risk,
            reports=reports,
            alerts_sent=alerts_sent,
            alert_errors=tuple(alert_errors),
        )
