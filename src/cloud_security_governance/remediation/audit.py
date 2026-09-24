"""Persistent remediation audit adapter."""

from __future__ import annotations

from cloud_security_governance.models import RemediationAction, RemediationStatus
from cloud_security_governance.remediation.core import RemediationAuditEvent, RemediationOutcome
from cloud_security_governance.storage import FindingStorage


class StorageAuditSink:
    """Append remediation audit events through the configured storage backend."""

    def __init__(self, storage: FindingStorage) -> None:
        self._storage = storage

    def record(self, event: RemediationAuditEvent) -> None:
        success = event.result is RemediationOutcome.SUCCEEDED
        failed = event.result in {
            RemediationOutcome.FAILED,
            RemediationOutcome.VERIFICATION_FAILED,
        }
        status = (
            RemediationStatus.COMPLETED
            if success
            else RemediationStatus.FAILED
            if failed
            else RemediationStatus.CANCELLED
        )
        self._storage.save_remediation_history(
            RemediationAction(
                action_id=event.audit_id,
                finding_id=event.finding_id,
                action_type=event.action,
                description=event.message,
                status=status,
                created_at=event.timestamp,
                updated_at=event.timestamp,
                started_at=event.timestamp if success or failed else None,
                completed_at=event.timestamp if success else None,
                error_message=event.message if failed else None,
                metadata={
                    "provider": event.provider.value,
                    "actor": event.actor,
                    "result": event.result.value,
                    "previous_state": event.previous_state,
                    "new_state": event.new_state,
                    "approval_id": str(event.approval_id) if event.approval_id else None,
                    "dry_run": event.dry_run,
                },
            )
        )
