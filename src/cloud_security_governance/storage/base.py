"""Provider-neutral persistence contract for security workflow data."""

from __future__ import annotations

from abc import ABC, abstractmethod
from collections.abc import Sequence
from uuid import UUID

from cloud_security_governance.models import (
    CloudProvider,
    Finding,
    FindingStatus,
    MultiCloudScanResult,
    RemediationAction,
    ScanResult,
)


class FindingStorage(ABC):
    """Storage operations required by the compliance workflow."""

    @abstractmethod
    def save_finding(self, finding: Finding) -> None: ...

    @abstractmethod
    def get_finding(self, finding_id: UUID | str) -> Finding | None: ...

    @abstractmethod
    def list_findings(
        self,
        *,
        provider: CloudProvider | None = None,
        status: FindingStatus | None = None,
        limit: int | None = None,
    ) -> Sequence[Finding]: ...

    @abstractmethod
    def update_finding_status(
        self,
        finding_id: UUID | str,
        status: FindingStatus,
    ) -> Finding: ...

    @abstractmethod
    def save_scan_metadata(self, scan: ScanResult | MultiCloudScanResult) -> None: ...

    @abstractmethod
    def get_scan_metadata(
        self, scan_id: UUID | str
    ) -> ScanResult | MultiCloudScanResult | None: ...

    @abstractmethod
    def save_remediation_history(self, action: RemediationAction) -> None: ...
