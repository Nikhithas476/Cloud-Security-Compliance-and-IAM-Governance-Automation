"""Fault-isolated orchestration for complete cloud security scanners."""

from __future__ import annotations

from collections.abc import Callable, Sequence
from datetime import UTC, datetime

from cloud_security_governance.base_scanner import BaseScanner
from cloud_security_governance.exceptions import CloudProviderError, ConfigurationError
from cloud_security_governance.models import CloudScanFailure, MultiCloudScanResult


def _utc_now() -> datetime:
    return datetime.now(UTC)


class ScannerOrchestrator:
    """Run independent cloud scans while preserving every successful result."""

    def __init__(
        self,
        scanners: Sequence[BaseScanner],
        *,
        clock: Callable[[], datetime] = _utc_now,
    ) -> None:
        if not scanners:
            raise ConfigurationError("At least one cloud scanner is required")
        providers = [scanner.provider for scanner in scanners]
        if len(providers) != len(set(providers)):
            raise ConfigurationError("Only one scanner per cloud provider is allowed")
        self.scanners = tuple(scanners)
        self._clock = clock

    def scan(self) -> MultiCloudScanResult:
        """Run configured scanners sequentially and isolate expected provider failures."""

        started_at = self._normalize_time(self._clock())
        results = []
        failures = []
        for scanner in self.scanners:
            try:
                result = scanner.scan()
                if result.account.provider is not scanner.provider:
                    raise CloudProviderError(
                        "The scanner returned a result for a different cloud provider"
                    )
                results.append(result)
            except CloudProviderError as exc:
                failures.append(
                    CloudScanFailure(
                        provider=scanner.provider,
                        error_type=type(exc).__name__,
                        message=self._failure_message(exc),
                    )
                )

        completed_at = max(self._normalize_time(self._clock()), started_at)
        findings = [finding for result in results for finding in result.findings]
        return MultiCloudScanResult(
            started_at=started_at,
            completed_at=completed_at,
            results=results,
            failures=failures,
            findings=findings,
            resources_scanned=sum(result.resources_scanned for result in results),
        )

    @staticmethod
    def _normalize_time(value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ConfigurationError("Orchestration timestamps must include timezone information")
        return value.astimezone(UTC)

    @staticmethod
    def _failure_message(error: CloudProviderError) -> str:
        message = str(error).strip() or "The cloud scan failed"
        return message[:512]
