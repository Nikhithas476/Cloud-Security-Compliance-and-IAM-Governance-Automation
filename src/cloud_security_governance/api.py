"""Authenticated FastAPI routes backed exclusively by application services."""

from __future__ import annotations

import logging
from typing import Annotated, Any
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from fastapi.security import HTTPAuthorizationCredentials
from pydantic import BaseModel, ConfigDict, Field

from cloud_security_governance import __version__
from cloud_security_governance.api_service import GovernanceAPIService
from cloud_security_governance.auth import (
    Principal,
    Role,
    authenticated_principal,
    authorize,
    bearer,
)
from cloud_security_governance.config import get_settings
from cloud_security_governance.exceptions import ApprovalError
from cloud_security_governance.models import CloudProvider, Finding, FindingStatus, Severity
from cloud_security_governance.remediation import (
    ApprovalRequest,
    ApprovalStatus,
    RemediationOutcome,
)

router = APIRouter()
logger = logging.getLogger(__name__)


class HealthResponse(BaseModel):
    status: str
    service: str
    environment: str
    version: str


class FindingResponse(BaseModel):
    finding_id: UUID
    rule_id: str
    cloud: CloudProvider
    resource_id: str
    resource_type: str
    title: str
    description: str
    severity: Severity
    status: FindingStatus
    remediation_available: bool

    @classmethod
    def from_finding(cls, finding: Finding) -> FindingResponse:
        return cls(
            finding_id=finding.finding_id,
            rule_id=finding.rule_id,
            cloud=finding.resource.provider,
            resource_id=finding.resource.resource_id,
            resource_type=finding.resource.resource_type,
            title=finding.title,
            description=finding.description,
            severity=finding.severity,
            status=finding.status,
            remediation_available=finding.remediation_available,
        )


class ScanResponse(BaseModel):
    scan_id: UUID
    resources_scanned: int
    findings_count: int
    failures: int = 0


class RemediationRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    action: str = Field(min_length=1, max_length=256, pattern=r"^[a-z0-9.-]+$")
    parameters: dict[str, Any] = Field(default_factory=dict)
    approval_id: UUID | None = None
    dry_run: bool = False


class RemediationResponse(BaseModel):
    finding_id: UUID
    action: str
    outcome: RemediationOutcome
    executed: bool
    verified: bool
    message: str


class ApprovalCreateRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    action: str = Field(min_length=1, max_length=256, pattern=r"^[a-z0-9.-]+$")
    parameters: dict[str, Any] = Field(default_factory=dict)


class ApprovalDecisionRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    notes: str | None = Field(default=None, max_length=2_000)


class ApprovalResponse(BaseModel):
    approval_id: UUID
    finding_id: UUID
    action: str
    requested_by: str
    reviewed_by: str | None
    status: ApprovalStatus
    requested_at: str
    reviewed_at: str | None
    review_notes: str | None

    @classmethod
    def from_approval(cls, approval: ApprovalRequest) -> ApprovalResponse:
        return cls(
            approval_id=approval.approval_id,
            finding_id=approval.finding_id,
            action=approval.action,
            requested_by=approval.requested_by,
            reviewed_by=approval.reviewed_by,
            status=approval.status,
            requested_at=approval.requested_at.isoformat(),
            reviewed_at=approval.reviewed_at.isoformat() if approval.reviewed_at else None,
            review_notes=approval.review_notes,
        )


def _service(request: Request) -> GovernanceAPIService:
    service = getattr(request.app.state, "api_service", None)
    if service is None:
        factory = getattr(request.app.state, "api_service_factory", None)
        if factory is None:
            raise HTTPException(status_code=503, detail="Service is not configured")
        try:
            service = factory()
        except Exception as exc:
            logger.error("service_bootstrap_failed type=%s", type(exc).__name__)
            raise HTTPException(status_code=503, detail="Service is unavailable") from exc
        request.app.state.api_service = service
    return service


def _principal(
    request: Request, credentials: Annotated[HTTPAuthorizationCredentials | None, Depends(bearer)]
) -> Principal:
    return authenticated_principal(request, credentials)


def _reader(principal: Annotated[Principal, Depends(_principal)]) -> Principal:
    return authorize(principal, Role.READER, Role.OPERATOR, Role.REVIEWER)


def _operator(principal: Annotated[Principal, Depends(_principal)]) -> Principal:
    return authorize(principal, Role.OPERATOR)


def _reviewer(principal: Annotated[Principal, Depends(_principal)]) -> Principal:
    return authorize(principal, Role.REVIEWER)


@router.get("/health", response_model=HealthResponse, tags=["system"])
def health() -> HealthResponse:
    settings = get_settings()
    return HealthResponse(
        status="ok", service=settings.app_name, environment=settings.app_env, version=__version__
    )


@router.post("/scans", response_model=ScanResponse, tags=["scans"])
def start_scan(
    request: Request, principal: Annotated[Principal, Depends(_operator)]
) -> ScanResponse:
    result = _service(request).start_scan()
    logger.info(
        "api_audit actor=%s action=start_scan scan_id=%s", principal.subject, result.scan.scan_id
    )
    return ScanResponse(
        scan_id=result.scan.scan_id,
        resources_scanned=result.scan.resources_scanned,
        findings_count=len(result.scan.findings),
        failures=len(result.scan.failures),
    )


@router.get("/scans/{scan_id}", response_model=ScanResponse, tags=["scans"])
def get_scan(
    scan_id: UUID, request: Request, principal: Annotated[Principal, Depends(_reader)]
) -> ScanResponse:
    scan = _service(request).get_scan(scan_id)
    if scan is None:
        raise HTTPException(status_code=404, detail="Scan not found")
    return ScanResponse(
        scan_id=scan.scan_id,
        resources_scanned=scan.resources_scanned,
        findings_count=len(scan.findings),
        failures=len(getattr(scan, "failures", [])),
    )


@router.get("/findings", response_model=list[FindingResponse], tags=["findings"])
def list_findings(
    request: Request,
    principal: Annotated[Principal, Depends(_reader)],
    provider: CloudProvider | None = None,
    status: FindingStatus | None = None,
    limit: Annotated[int, Query(ge=1, le=500)] = 100,
) -> list[FindingResponse]:
    return [
        FindingResponse.from_finding(item)
        for item in _service(request).list_findings(provider=provider, status=status, limit=limit)
    ]


@router.get("/findings/{finding_id}", response_model=FindingResponse, tags=["findings"])
def get_finding(
    finding_id: UUID, request: Request, principal: Annotated[Principal, Depends(_reader)]
) -> FindingResponse:
    finding = _service(request).get_finding(finding_id)
    if finding is None:
        raise HTTPException(status_code=404, detail="Finding not found")
    return FindingResponse.from_finding(finding)


@router.get("/reports/{scan_id}", response_model=dict[str, str], tags=["reports"])
def get_reports(
    scan_id: UUID, request: Request, principal: Annotated[Principal, Depends(_reader)]
) -> dict[str, str]:
    reports = _service(request).get_reports(scan_id)
    if reports is None:
        raise HTTPException(status_code=404, detail="Report not found")
    return reports


@router.post("/approvals/{finding_id}", response_model=ApprovalResponse, tags=["remediation"])
def request_approval(
    finding_id: UUID,
    payload: ApprovalCreateRequest,
    request: Request,
    principal: Annotated[Principal, Depends(_operator)],
) -> ApprovalResponse:
    review = _service(request).request_approval(
        finding_id,
        action=payload.action,
        parameters=payload.parameters,
        requested_by=principal.subject,
    )
    if review is None:
        raise HTTPException(status_code=404, detail="Finding not found")
    logger.info(
        "api_audit actor=%s action=request_approval approval_id=%s",
        principal.subject,
        review.approval.approval_id,
    )
    return ApprovalResponse.from_approval(review.approval)


@router.get("/approvals/{approval_id}", response_model=ApprovalResponse, tags=["remediation"])
def get_approval(
    approval_id: UUID,
    request: Request,
    principal: Annotated[Principal, Depends(_reader)],
) -> ApprovalResponse:
    del principal
    try:
        approval = _service(request).get_approval(approval_id)
    except ApprovalError as exc:
        raise HTTPException(status_code=404, detail="Approval not found") from exc
    return ApprovalResponse.from_approval(approval)


@router.post(
    "/approvals/{approval_id}/approve",
    response_model=ApprovalResponse,
    tags=["remediation"],
)
def approve_remediation(
    approval_id: UUID,
    payload: ApprovalDecisionRequest,
    request: Request,
    principal: Annotated[Principal, Depends(_reviewer)],
) -> ApprovalResponse:
    try:
        approval = _service(request).approve(approval_id, principal.subject, payload.notes)
    except ApprovalError as exc:
        raise HTTPException(status_code=409, detail="Approval cannot be approved") from exc
    logger.info("api_audit actor=%s action=approve approval_id=%s", principal.subject, approval_id)
    return ApprovalResponse.from_approval(approval)


@router.post(
    "/approvals/{approval_id}/reject",
    response_model=ApprovalResponse,
    tags=["remediation"],
)
def reject_remediation(
    approval_id: UUID,
    payload: ApprovalDecisionRequest,
    request: Request,
    principal: Annotated[Principal, Depends(_reviewer)],
) -> ApprovalResponse:
    try:
        approval = _service(request).reject(approval_id, principal.subject, payload.notes)
    except ApprovalError as exc:
        raise HTTPException(status_code=409, detail="Approval cannot be rejected") from exc
    logger.info("api_audit actor=%s action=reject approval_id=%s", principal.subject, approval_id)
    return ApprovalResponse.from_approval(approval)


@router.post("/remediation/{finding_id}", response_model=RemediationResponse, tags=["remediation"])
def remediate(
    finding_id: UUID,
    payload: RemediationRequest,
    request: Request,
    principal: Annotated[Principal, Depends(_operator)],
) -> RemediationResponse:
    if not payload.dry_run and payload.approval_id is None:
        raise HTTPException(status_code=403, detail="Explicit approval is required")
    result = _service(request).remediate(
        finding_id,
        action=payload.action,
        actor=principal.subject,
        parameters=payload.parameters,
        approval_id=payload.approval_id,
        dry_run=payload.dry_run,
    )
    if result is None:
        raise HTTPException(status_code=404, detail="Finding not found")
    logger.info(
        "api_audit actor=%s action=remediate finding_id=%s outcome=%s",
        principal.subject,
        finding_id,
        result.outcome.value,
    )
    if result.outcome is RemediationOutcome.NOT_APPROVED:
        raise HTTPException(status_code=403, detail="Approval is invalid or has already been used")
    return RemediationResponse(
        finding_id=result.finding_id,
        action=result.action,
        outcome=result.outcome,
        executed=result.executed,
        verified=result.verified,
        message=result.message,
    )
