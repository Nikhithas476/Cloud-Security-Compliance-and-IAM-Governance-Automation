"""Audit-oriented JSON, CSV, and HTML compliance report generation."""

from __future__ import annotations

import csv
import io
import json
from collections.abc import Iterable
from dataclasses import dataclass
from html import escape
from typing import Any

from cloud_security_governance.models import (
    CloudProvider,
    ComplianceReport,
    Finding,
    RemediationAction,
    RemediationStatus,
    Severity,
)
from cloud_security_governance.risk import RiskScore


@dataclass(frozen=True)
class GeneratedReports:
    """All supported report representations for one workflow run."""

    json_report: str
    csv_report: str
    html_report: str


class ComplianceReportGenerator:
    """Render normalized compliance and risk results for security review."""

    def generate(
        self,
        compliance: ComplianceReport,
        risk: RiskScore,
        *,
        remediation_history: Iterable[RemediationAction] = (),
    ) -> GeneratedReports:
        payload = self._payload(compliance, risk, remediation_history)
        return GeneratedReports(
            json_report=json.dumps(payload, indent=2, sort_keys=True),
            csv_report=self._csv(payload),
            html_report=self._html(payload),
        )

    def generate_json(
        self,
        compliance: ComplianceReport,
        risk: RiskScore,
        *,
        remediation_history: Iterable[RemediationAction] = (),
    ) -> str:
        return self.generate(compliance, risk, remediation_history=remediation_history).json_report

    def generate_csv(
        self,
        compliance: ComplianceReport,
        risk: RiskScore,
        *,
        remediation_history: Iterable[RemediationAction] = (),
    ) -> str:
        return self.generate(compliance, risk, remediation_history=remediation_history).csv_report

    def generate_html(
        self,
        compliance: ComplianceReport,
        risk: RiskScore,
        *,
        remediation_history: Iterable[RemediationAction] = (),
    ) -> str:
        return self.generate(compliance, risk, remediation_history=remediation_history).html_report

    @classmethod
    def _payload(
        cls,
        compliance: ComplianceReport,
        risk: RiskScore,
        remediation_history: Iterable[RemediationAction],
    ) -> dict[str, Any]:
        actions = [RemediationAction.model_validate(action) for action in remediation_history]
        latest_actions: dict[str, RemediationAction] = {}
        for action in sorted(actions, key=lambda value: value.created_at):
            latest_actions[str(action.finding_id)] = action

        findings_by_id: dict[str, Finding] = {}
        for result in compliance.results:
            for finding in result.findings:
                findings_by_id.setdefault(str(finding.finding_id), finding)
        for finding in compliance.unmatched_findings:
            findings_by_id.setdefault(str(finding.finding_id), finding)
        findings = list(findings_by_id.values())

        finding_rows = [cls._finding_row(finding, latest_actions) for finding in findings]
        compliance_percentage = (
            round(compliance.compliant_rules / compliance.rules_evaluated * 100, 2)
            if compliance.rules_evaluated
            else 100.0
        )
        remediation_summary = {status.value: 0 for status in RemediationStatus}
        remediation_summary["not_started"] = 0
        for row in finding_rows:
            remediation_summary[row["remediation_status"]] += 1

        summary = (
            f"Evaluated {compliance.rules_evaluated} enabled controls with "
            f"{compliance.non_compliant_rules} non-compliant controls and "
            f"{len(findings)} unique findings. Overall risk is "
            f"{risk.overall_risk_score}/100."
        )
        return {
            "executive_summary": summary,
            "overall_compliance": {
                "percentage": compliance_percentage,
                "rules_evaluated": compliance.rules_evaluated,
                "compliant_rules": compliance.compliant_rules,
                "non_compliant_rules": compliance.non_compliant_rules,
                "unmatched_findings": len(compliance.unmatched_findings),
            },
            "risk_score": risk.model_dump(mode="json"),
            "critical_findings": [
                row for row in finding_rows if row["severity"] == Severity.CRITICAL.value
            ],
            "high_findings": [
                row for row in finding_rows if row["severity"] == Severity.HIGH.value
            ],
            "medium_findings": [
                row for row in finding_rows if row["severity"] == Severity.MEDIUM.value
            ],
            "aws_findings": [
                row for row in finding_rows if row["cloud"] == CloudProvider.AWS.value
            ],
            "azure_findings": [
                row for row in finding_rows if row["cloud"] == CloudProvider.AZURE.value
            ],
            "remediation_status": remediation_summary,
            "all_findings": finding_rows,
        }

    @staticmethod
    def _finding_row(
        finding: Finding,
        latest_actions: dict[str, RemediationAction],
    ) -> dict[str, Any]:
        action = latest_actions.get(str(finding.finding_id))
        return {
            "finding_id": str(finding.finding_id),
            "cloud": finding.resource.provider.value,
            "account_or_subscription": finding.resource.account_id,
            "resource": finding.resource.resource_id,
            "rule": finding.rule_id,
            "severity": finding.severity.value,
            "title": finding.title,
            "description": finding.description,
            "finding_status": finding.status.value,
            "remediation_status": action.status.value if action else "not_started",
            "detected_at": finding.detected_at.isoformat(),
        }

    @staticmethod
    def _csv(payload: dict[str, Any]) -> str:
        output = io.StringIO(newline="")
        writer = csv.writer(output, lineterminator="\n")
        writer.writerow(["Executive Summary", payload["executive_summary"]])
        writer.writerow(["Overall Compliance", payload["overall_compliance"]["percentage"]])
        writer.writerow(["Overall Risk Score", payload["risk_score"]["overall_risk_score"]])
        writer.writerow(["Critical Findings", len(payload["critical_findings"])])
        writer.writerow(["High Findings", len(payload["high_findings"])])
        writer.writerow(["Medium Findings", len(payload["medium_findings"])])
        writer.writerow(["AWS Findings", len(payload["aws_findings"])])
        writer.writerow(["Azure Findings", len(payload["azure_findings"])])
        writer.writerow(
            ["Remediation Status", json.dumps(payload["remediation_status"], sort_keys=True)]
        )
        writer.writerow([])
        fields = [
            "finding_id",
            "cloud",
            "account_or_subscription",
            "resource",
            "rule",
            "severity",
            "title",
            "description",
            "finding_status",
            "remediation_status",
            "detected_at",
        ]
        writer.writerow(fields)
        for row in payload["all_findings"]:
            writer.writerow([row[field] for field in fields])
        return output.getvalue()

    @staticmethod
    def _html(payload: dict[str, Any]) -> str:
        summary = payload["overall_compliance"]
        risk = payload["risk_score"]
        finding_rows = "".join(
            "<tr>"
            + "".join(
                f"<td>{escape(str(row[field]))}</td>"
                for field in (
                    "severity",
                    "cloud",
                    "account_or_subscription",
                    "resource",
                    "rule",
                    "title",
                    "description",
                    "remediation_status",
                    "finding_id",
                )
            )
            + "</tr>"
            for row in payload["all_findings"]
        )
        return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8"><title>Cloud Compliance Report</title>
<style>body{{font-family:Arial,sans-serif;margin:2rem;color:#172033}}table{{border-collapse:collapse;width:100%}}th,td{{border:1px solid #ccd3df;padding:.5rem;text-align:left;vertical-align:top}}th{{background:#eef2f7}}.metrics{{display:flex;gap:1rem;flex-wrap:wrap}}.metric{{border:1px solid #ccd3df;border-radius:6px;padding:1rem}}</style></head>
<body><h1>Cloud Security Compliance Report</h1><h2>Executive Summary</h2>
<p>{escape(payload["executive_summary"])}</p><div class="metrics">
<div class="metric"><strong>Overall compliance</strong><br>{summary["percentage"]}%</div>
<div class="metric"><strong>Overall risk score</strong><br>{risk["overall_risk_score"]}/100</div>
<div class="metric"><strong>AWS risk</strong><br>{risk["aws_risk_score"]}/100</div>
<div class="metric"><strong>Azure risk</strong><br>{risk["azure_risk_score"]}/100</div></div>
<h2>Finding Summary</h2><p>Critical: {len(payload["critical_findings"])} | High: {len(payload["high_findings"])} | Medium: {len(payload["medium_findings"])} | AWS: {len(payload["aws_findings"])} | Azure: {len(payload["azure_findings"])}</p>
<h2>Remediation Status</h2><pre>{escape(json.dumps(payload["remediation_status"], indent=2, sort_keys=True))}</pre>
<h2>Findings</h2><table><thead><tr><th>Severity</th><th>Cloud</th><th>Account / Subscription</th><th>Resource</th><th>Rule</th><th>Title</th><th>Description</th><th>Remediation</th><th>Finding ID</th></tr></thead><tbody>{finding_rows}</tbody></table></body></html>"""
