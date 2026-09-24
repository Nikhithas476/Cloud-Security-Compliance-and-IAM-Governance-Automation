"""Approval-gated remediation framework and cloud-specific actions."""

from cloud_security_governance.remediation.audit import StorageAuditSink
from cloud_security_governance.remediation.core import (
    ApprovalRequest,
    ApprovalService,
    ApprovalStatus,
    InMemoryAuditSink,
    RemediationAuditEvent,
    RemediationEngine,
    RemediationExecutor,
    RemediationOutcome,
    RemediationResult,
    RemediationReview,
)

__all__ = [
    "ApprovalRequest",
    "ApprovalService",
    "ApprovalStatus",
    "InMemoryAuditSink",
    "RemediationAuditEvent",
    "RemediationEngine",
    "RemediationExecutor",
    "RemediationOutcome",
    "RemediationResult",
    "RemediationReview",
    "StorageAuditSink",
]
