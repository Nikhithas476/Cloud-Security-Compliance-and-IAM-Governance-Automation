"""Deterministic weighted risk scoring for normalized cloud findings.

Each unique finding contributes its configured severity weight. Scores are the sum of those
weights capped at 100. Overall, AWS, and Azure scores use the same formula over their respective
finding sets. Informational findings are counted in the distribution but contribute zero points.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, StrictInt, model_validator

from cloud_security_governance.models import CloudProvider, Finding, Severity

MAX_RISK_SCORE = 100


class RiskWeights(BaseModel):
    """Validated point values for risk-bearing finding severities."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    critical: StrictInt = Field(default=25, ge=0, le=MAX_RISK_SCORE)
    high: StrictInt = Field(default=10, ge=0, le=MAX_RISK_SCORE)
    medium: StrictInt = Field(default=5, ge=0, le=MAX_RISK_SCORE)
    low: StrictInt = Field(default=1, ge=0, le=MAX_RISK_SCORE)

    def for_severity(self, severity: Severity) -> int:
        """Return the configured weight, with informational findings worth zero."""

        if severity is Severity.INFORMATIONAL:
            return 0
        return {
            Severity.CRITICAL: self.critical,
            Severity.HIGH: self.high,
            Severity.MEDIUM: self.medium,
            Severity.LOW: self.low,
        }[severity]


class SeverityDistribution(BaseModel):
    """Counts of unique findings by normalized severity."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    critical: int = Field(ge=0)
    high: int = Field(ge=0)
    medium: int = Field(ge=0)
    low: int = Field(ge=0)
    informational: int = Field(ge=0)


class RiskScore(BaseModel):
    """Normalized multi-cloud risk scores and their source distribution."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    overall_risk_score: int = Field(ge=0, le=MAX_RISK_SCORE)
    aws_risk_score: int = Field(ge=0, le=MAX_RISK_SCORE)
    azure_risk_score: int = Field(ge=0, le=MAX_RISK_SCORE)
    severity_distribution: SeverityDistribution
    findings_scored: int = Field(ge=0)

    @model_validator(mode="after")
    def distribution_must_match_findings(self) -> RiskScore:
        distribution_total = sum(
            (
                self.severity_distribution.critical,
                self.severity_distribution.high,
                self.severity_distribution.medium,
                self.severity_distribution.low,
                self.severity_distribution.informational,
            )
        )
        if distribution_total != self.findings_scored:
            raise ValueError("severity distribution must match findings_scored")
        return self


class RiskCalculator:
    """Calculate order-independent 0–100 risk scores from normalized findings."""

    def __init__(self, weights: RiskWeights | Mapping[str, Any] | None = None) -> None:
        self.weights = RiskWeights.model_validate(weights or {})

    def calculate(self, findings: Iterable[Finding]) -> RiskScore:
        """Score unique finding IDs overall and independently for AWS and Azure."""

        unique: dict[object, Finding] = {}
        for item in findings:
            normalized = Finding.model_validate(item)
            unique.setdefault(normalized.finding_id, normalized)
        normalized_findings = tuple(unique.values())

        distribution = {severity: 0 for severity in Severity}
        for finding in normalized_findings:
            distribution[finding.severity] += 1

        return RiskScore(
            overall_risk_score=self._score(normalized_findings),
            aws_risk_score=self._score(
                finding
                for finding in normalized_findings
                if finding.resource.provider is CloudProvider.AWS
            ),
            azure_risk_score=self._score(
                finding
                for finding in normalized_findings
                if finding.resource.provider is CloudProvider.AZURE
            ),
            severity_distribution=SeverityDistribution(
                critical=distribution[Severity.CRITICAL],
                high=distribution[Severity.HIGH],
                medium=distribution[Severity.MEDIUM],
                low=distribution[Severity.LOW],
                informational=distribution[Severity.INFORMATIONAL],
            ),
            findings_scored=len(normalized_findings),
        )

    def _score(self, findings: Iterable[Finding]) -> int:
        raw_score = sum(self.weights.for_severity(finding.severity) for finding in findings)
        return min(MAX_RISK_SCORE, raw_score)
