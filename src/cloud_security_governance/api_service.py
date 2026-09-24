"""Application-service facade used by HTTP delivery adapters."""

from __future__ import annotations

from dataclasses import dataclass, field
from uuid import UUID

from cloud_security_governance.models import CloudProvider, Finding, FindingStatus
from cloud_security_governance.remediation import RemediationEngine, RemediationResult
from cloud_security_governance.storage import FindingStorage
from cloud_security_governance.workflow import ComplianceWorkflowResult, ComplianceWorkflowService


@dataclass
class GovernanceAPIService:
    workflow: ComplianceWorkflowService
    storage: FindingStorage
    remediation: RemediationEngine
    _reports: dict[UUID, dict[str, str]] = field(default_factory=dict, init=False)

    def start_scan(self) -> ComplianceWorkflowResult:
        result = self.workflow.run()
        self._reports[result.scan.scan_id] = {
            "json": result.reports.json_report,
            "csv": result.reports.csv_report,
            "html": result.reports.html_report,
        }
        return result

    def get_scan(self, scan_id: UUID):
        return self.storage.get_scan_metadata(scan_id)

    def list_findings(
        self, *, provider: CloudProvider | None, status: FindingStatus | None, limit: int
    ):
        return self.storage.list_findings(provider=provider, status=status, limit=limit)

    def get_finding(self, finding_id: UUID) -> Finding | None:
        return self.storage.get_finding(finding_id)

    def get_reports(self, scan_id: UUID) -> dict[str, str] | None:
        return self._reports.get(scan_id)

    def remediate(
        self,
        finding_id: UUID,
        *,
        action: str,
        actor: str,
        parameters: dict,
        approval_id: UUID | None,
        dry_run: bool,
    ) -> RemediationResult | None:
        finding = self.storage.get_finding(finding_id)
        if finding is None:
            return None
        return self.remediation.remediate(
            finding, action, actor, parameters, approval_id=approval_id, dry_run=dry_run
        )
