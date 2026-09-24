"""Provider-neutral, explicit-approval remediation lifecycle."""

from __future__ import annotations

import hashlib
import json
import logging
from abc import ABC, abstractmethod
from collections.abc import Callable
from datetime import UTC, datetime
from enum import StrEnum
from threading import RLock
from typing import Annotated, Any, Protocol
from uuid import UUID, uuid4

from pydantic import BaseModel, ConfigDict, Field, StringConstraints

from cloud_security_governance.exceptions import ApprovalError
from cloud_security_governance.models import CloudProvider, Finding

Actor = Annotated[str, StringConstraints(strip_whitespace=True, min_length=1, max_length=256)]
ActionName = Annotated[
    str,
    StringConstraints(
        strip_whitespace=True, min_length=1, max_length=256, pattern=r"^[a-z0-9.-]+$"
    ),
]
JsonObject = dict[str, Any]


def _now() -> datetime:
    return datetime.now(UTC)


def _fingerprint(finding_id: UUID, action: str, parameters: JsonObject) -> str:
    payload = json.dumps(
        {"finding_id": str(finding_id), "action": action, "parameters": parameters},
        sort_keys=True,
        separators=(",", ":"),
    )
    return hashlib.sha256(payload.encode()).hexdigest()


class _Model(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, str_strip_whitespace=True)


class ApprovalStatus(StrEnum):
    PENDING = "pending"
    APPROVED = "approved"
    REJECTED = "rejected"
    CONSUMED = "consumed"


class RemediationOutcome(StrEnum):
    NOT_APPROVED = "not_approved"
    DRY_RUN = "dry_run"
    SUCCEEDED = "succeeded"
    VERIFICATION_FAILED = "verification_failed"
    FAILED = "failed"


class ApprovalRequest(_Model):
    approval_id: UUID = Field(default_factory=uuid4)
    finding_id: UUID
    action: ActionName
    request_fingerprint: str = Field(min_length=64, max_length=64)
    requested_by: Actor
    requested_at: datetime = Field(default_factory=_now)
    reviewed_by: Actor | None = None
    reviewed_at: datetime | None = None
    review_notes: str | None = Field(default=None, max_length=2_000)
    status: ApprovalStatus = ApprovalStatus.PENDING


class RemediationReview(_Model):
    finding_id: UUID
    action: ActionName
    previous_state: JsonObject
    approval: ApprovalRequest


class RemediationAuditEvent(_Model):
    audit_id: UUID = Field(default_factory=uuid4)
    finding_id: UUID
    action: ActionName
    provider: CloudProvider
    actor: Actor
    timestamp: datetime = Field(default_factory=_now)
    result: RemediationOutcome
    previous_state: JsonObject = Field(default_factory=dict)
    new_state: JsonObject = Field(default_factory=dict)
    approval_id: UUID | None = None
    dry_run: bool = False
    message: str = Field(min_length=1, max_length=2_000)


class RemediationResult(_Model):
    finding_id: UUID
    action: ActionName
    provider: CloudProvider
    actor: Actor
    outcome: RemediationOutcome
    approved: bool
    dry_run: bool
    executed: bool
    verified: bool
    previous_state: JsonObject = Field(default_factory=dict)
    new_state: JsonObject = Field(default_factory=dict)
    approval_id: UUID | None = None
    started_at: datetime
    completed_at: datetime
    message: str


class ApprovalService:
    """Thread-safe, one-time approvals bound to an exact action and parameters."""

    def __init__(self, clock: Callable[[], datetime] = _now) -> None:
        self._clock = clock
        self._requests: dict[UUID, ApprovalRequest] = {}
        self._lock = RLock()

    def request(
        self, finding_id: UUID, action: str, parameters: JsonObject, requested_by: str
    ) -> ApprovalRequest:
        request = ApprovalRequest(
            finding_id=finding_id,
            action=action,
            request_fingerprint=_fingerprint(finding_id, action, parameters),
            requested_by=requested_by,
            requested_at=self._clock(),
        )
        with self._lock:
            self._requests[request.approval_id] = request
        return request

    def approve(self, approval_id: UUID, actor: str, notes: str | None = None) -> ApprovalRequest:
        return self._decide(approval_id, actor, ApprovalStatus.APPROVED, notes)

    def reject(self, approval_id: UUID, actor: str, notes: str | None = None) -> ApprovalRequest:
        return self._decide(approval_id, actor, ApprovalStatus.REJECTED, notes)

    def _decide(
        self, approval_id: UUID, actor: str, status: ApprovalStatus, notes: str | None
    ) -> ApprovalRequest:
        with self._lock:
            request = self._get(approval_id)
            if request.status is not ApprovalStatus.PENDING:
                raise ApprovalError("Only a pending approval request can be decided")
            updated = ApprovalRequest.model_validate(
                {
                    **request.model_dump(),
                    "status": status,
                    "reviewed_by": actor.strip(),
                    "reviewed_at": self._clock(),
                    "review_notes": notes,
                }
            )
            self._requests[approval_id] = updated
            return updated

    def consume(
        self, approval_id: UUID, finding_id: UUID, action: str, parameters: JsonObject
    ) -> ApprovalRequest:
        with self._lock:
            request = self._get(approval_id)
            expected = _fingerprint(finding_id, action, parameters)
            if request.status is not ApprovalStatus.APPROVED:
                raise ApprovalError("The remediation request has not been explicitly approved")
            if request.request_fingerprint != expected:
                raise ApprovalError("The approval does not match this remediation request")
            consumed = ApprovalRequest.model_validate(
                {**request.model_dump(), "status": ApprovalStatus.CONSUMED}
            )
            self._requests[approval_id] = consumed
            return consumed

    def _get(self, approval_id: UUID) -> ApprovalRequest:
        try:
            return self._requests[approval_id]
        except KeyError as exc:
            raise ApprovalError("The approval request does not exist") from exc


class RemediationExecutor(ABC):
    """One narrowly scoped cloud mutation with mandatory state verification."""

    provider: CloudProvider
    action: str

    @abstractmethod
    def review(self, finding: Finding, parameters: JsonObject) -> JsonObject: ...

    @abstractmethod
    def execute(self, finding: Finding, parameters: JsonObject) -> JsonObject: ...

    @abstractmethod
    def verify(self, finding: Finding, parameters: JsonObject) -> tuple[bool, JsonObject]: ...


class InMemoryAuditSink:
    """Append-only audit sink useful for local operation and composition."""

    def __init__(self) -> None:
        self.events: list[RemediationAuditEvent] = []

    def record(self, event: RemediationAuditEvent) -> None:
        self.events.append(event)


class AuditSink(Protocol):
    def record(self, event: RemediationAuditEvent) -> None: ...


class RemediationEngine:
    """Enforce review, approval, execution and verification in that order."""

    def __init__(
        self,
        approval_service: ApprovalService,
        executors: list[RemediationExecutor],
        audit_sink: AuditSink | None = None,
        clock: Callable[[], datetime] = _now,
    ) -> None:
        self.approvals = approval_service
        self.audit_sink = audit_sink or InMemoryAuditSink()
        self._clock = clock
        self._executors = {(item.provider, item.action): item for item in executors}
        if len(self._executors) != len(executors):
            raise ValueError("Each provider remediation action must be registered once")

    def review_and_request(
        self, finding: Finding, action: str, parameters: JsonObject, requested_by: str
    ) -> RemediationReview:
        executor = self._executor(finding, action)
        previous = executor.review(finding, parameters)
        approval = self.approvals.request(finding.finding_id, action, parameters, requested_by)
        return RemediationReview(
            finding_id=finding.finding_id,
            action=action,
            previous_state=previous,
            approval=approval,
        )

    def remediate(
        self,
        finding: Finding,
        action: str,
        actor: str,
        parameters: JsonObject,
        *,
        approval_id: UUID | None = None,
        dry_run: bool = False,
    ) -> RemediationResult:
        started = self._clock()
        previous: JsonObject = {}
        new: JsonObject = {}
        approved = executed = verified = False
        outcome = RemediationOutcome.FAILED
        message = "Remediation failed"
        try:
            executor = self._executor(finding, action)
            previous = executor.review(finding, parameters)
            if dry_run:
                outcome = RemediationOutcome.DRY_RUN
                message = "Dry run completed; no resource was modified"
            elif approval_id is None:
                outcome = RemediationOutcome.NOT_APPROVED
                message = "Remediation was not executed because explicit approval is required"
            else:
                self.approvals.consume(approval_id, finding.finding_id, action, parameters)
                approved = True
                new = executor.execute(finding, parameters)
                executed = True
                verified, verified_state = executor.verify(finding, parameters)
                new = verified_state or new
                if verified:
                    outcome = RemediationOutcome.SUCCEEDED
                    message = "Approved remediation completed and was verified"
                else:
                    outcome = RemediationOutcome.VERIFICATION_FAILED
                    message = "Resource state could not be verified after remediation"
        except ApprovalError as exc:
            outcome = RemediationOutcome.NOT_APPROVED
            message = str(exc)
        except Exception as exc:  # provider SDK exceptions are sanitized at this boundary
            logging.getLogger(__name__).exception("remediation execution failed")
            message = f"Remediation failed ({type(exc).__name__})"

        completed = self._clock()
        result = RemediationResult(
            finding_id=finding.finding_id,
            action=action,
            provider=finding.resource.provider,
            actor=actor,
            outcome=outcome,
            approved=approved,
            dry_run=dry_run,
            executed=executed,
            verified=verified,
            previous_state=previous,
            new_state=new,
            approval_id=approval_id,
            started_at=started,
            completed_at=completed,
            message=message,
        )
        event = RemediationAuditEvent(
            finding_id=finding.finding_id,
            action=action,
            provider=finding.resource.provider,
            actor=actor,
            result=outcome,
            previous_state=previous,
            new_state=new,
            approval_id=approval_id,
            dry_run=dry_run,
            message=message,
            timestamp=completed,
        )
        self.audit_sink.record(event)
        logging.getLogger(__name__).info("remediation_audit %s", event.model_dump_json())
        return result

    def _executor(self, finding: Finding, action: str) -> RemediationExecutor:
        try:
            return self._executors[(finding.resource.provider, action)]
        except KeyError as exc:
            raise ValueError("No controlled remediation is registered for this action") from exc
