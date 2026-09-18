"""Provider-neutral contract for complete cloud security scanners."""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import ClassVar

from cloud_security_governance.models import CloudProvider, ScanResult


class BaseScanner(ABC):
    """Contract implemented by complete cloud-provider scanners."""

    provider: ClassVar[CloudProvider]

    @abstractmethod
    def scan(self) -> ScanResult:
        """Run a read-only cloud scan and return its normalized result."""

