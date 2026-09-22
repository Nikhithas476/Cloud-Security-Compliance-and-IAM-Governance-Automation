"""Provider-neutral compliance evaluation over normalized scanner findings."""

from __future__ import annotations

from collections.abc import Callable, Iterable
from datetime import UTC, datetime
from pathlib import Path

from cloud_security_governance.exceptions import ConfigurationError
from cloud_security_governance.models import (
    ComplianceReport,
    ComplianceResult,
    ComplianceStatus,
    Finding,
)
from cloud_security_governance.rule_loader import (
    RuleConfiguration,
    RuleDefinition,
    load_rules,
)


def _utc_now() -> datetime:
    return datetime.now(UTC)


class RuleEvaluator:
    """Match normalized findings and evaluate one enabled compliance rule."""

    def __init__(self, rule: RuleDefinition) -> None:
        if not rule.enabled:
            raise ConfigurationError("RuleEvaluator requires an enabled compliance rule")
        self.rule = rule

    def matches(self, finding: Finding) -> bool:
        """Return whether a finding belongs to this rule and cloud."""

        return (
            finding.resource.provider is self.rule.cloud
            and self.rule.matches(finding.rule_id)
        )

    def evaluate(
        self,
        findings: Iterable[Finding],
        *,
        evaluated_at: datetime,
    ) -> ComplianceResult:
        """Return a compliant result when no matching violation findings exist."""

        normalized_time = self._normalize_time(evaluated_at)
        matches = [finding for finding in findings if self.matches(finding)]
        status = (
            ComplianceStatus.NON_COMPLIANT if matches else ComplianceStatus.COMPLIANT
        )
        return ComplianceResult(
            rule_id=self.rule.rule_id,
            rule_name=self.rule.name,
            cloud=self.rule.cloud,
            severity=self.rule.severity,
            description=self.rule.description,
            status=status,
            remediation_available=self.rule.remediation_available,
            findings=matches,
            evaluated_at=normalized_time,
        )

    @staticmethod
    def _normalize_time(value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ConfigurationError("Compliance evaluation timestamps must include timezone information")
        return value.astimezone(UTC)


class ComplianceEngine:
    """Load enabled rules and evaluate normalized multi-cloud scanner findings."""

    def __init__(
        self,
        *,
        rules_path: str | Path = Path("config/rules.yaml"),
        rule_loader: Callable[[str | Path], RuleConfiguration] = load_rules,
        clock: Callable[[], datetime] = _utc_now,
    ) -> None:
        self.rules_path = Path(rules_path)
        self._rule_loader = rule_loader
        self._clock = clock

    def evaluate(self, findings: Iterable[Finding]) -> ComplianceReport:
        """Evaluate findings once against every enabled configured rule."""

        evaluated_at = RuleEvaluator._normalize_time(self._clock())
        configuration = self._rule_loader(self.rules_path)
        enabled_rules = tuple(rule for rule in configuration.rules if rule.enabled)
        normalized_findings = [Finding.model_validate(finding) for finding in findings]
        assignments: dict[str, list[Finding]] = {rule.rule_id: [] for rule in enabled_rules}
        unmatched: list[Finding] = []

        for finding in normalized_findings:
            rule = self._select_rule(finding, enabled_rules)
            if rule is None:
                unmatched.append(finding)
            else:
                assignments[rule.rule_id].append(finding)

        results = [
            RuleEvaluator(rule).evaluate(assignments[rule.rule_id], evaluated_at=evaluated_at)
            for rule in enabled_rules
        ]
        compliant = sum(result.status is ComplianceStatus.COMPLIANT for result in results)
        non_compliant = len(results) - compliant
        return ComplianceReport(
            evaluated_at=evaluated_at,
            results=results,
            unmatched_findings=unmatched,
            rules_evaluated=len(results),
            compliant_rules=compliant,
            non_compliant_rules=non_compliant,
            matched_findings=sum(len(result.findings) for result in results),
        )

    @staticmethod
    def _select_rule(
        finding: Finding,
        rules: tuple[RuleDefinition, ...],
    ) -> RuleDefinition | None:
        candidates = [
            rule
            for rule in rules
            if rule.cloud is finding.resource.provider and rule.matches(finding.rule_id)
        ]
        if not candidates:
            return None
        exact = [rule for rule in candidates if not rule.rule_id.endswith(".*")]
        if exact:
            return exact[0]
        return max(candidates, key=lambda rule: len(rule.rule_id))
