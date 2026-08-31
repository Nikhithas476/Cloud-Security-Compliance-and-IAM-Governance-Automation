"""Enumerations shared by the security domain models."""

from enum import StrEnum


class CloudProvider(StrEnum):
    """Supported cloud platforms."""

    AWS = "aws"
    AZURE = "azure"


class Severity(StrEnum):
    """Normalized severity assigned to a compliance finding or rule."""

    INFORMATIONAL = "informational"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class FindingStatus(StrEnum):
    """Lifecycle state of a security finding."""

    OPEN = "open"
    ACKNOWLEDGED = "acknowledged"
    RESOLVED = "resolved"
    SUPPRESSED = "suppressed"


class RemediationStatus(StrEnum):
    """Execution state of a remediation action."""

    PENDING = "pending"
    IN_PROGRESS = "in_progress"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"

