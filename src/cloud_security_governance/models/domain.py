"""Validated security, compliance, and IAM governance domain models."""

from __future__ import annotations

import re
from datetime import UTC, datetime
from math import isfinite
from typing import Annotated, Any, Self
from uuid import UUID, uuid4

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    StringConstraints,
    field_validator,
    model_validator,
)

from cloud_security_governance.models.enums import (
    CloudProvider,
    FindingStatus,
    RemediationStatus,
    Severity,
)

Identifier = Annotated[
    str,
    StringConstraints(
        strip_whitespace=True,
        min_length=1,
        max_length=256,
        pattern=r"^[A-Za-z0-9][A-Za-z0-9_.:/@-]*$",
    ),
]
ResourceIdentifier = Annotated[
    str,
    StringConstraints(
        strip_whitespace=True,
        min_length=1,
        max_length=2_048,
        pattern=r"^/?[A-Za-z0-9][A-Za-z0-9_.:/@-]*$",
    ),
]
ShortText = Annotated[str, StringConstraints(strip_whitespace=True, min_length=1, max_length=512)]
LongText = Annotated[str, StringConstraints(strip_whitespace=True, min_length=1, max_length=10_000)]
Region = Annotated[
    str,
    StringConstraints(
        strip_whitespace=True,
        min_length=1,
        max_length=128,
        pattern=r"^[A-Za-z0-9][A-Za-z0-9_.-]*$",
    ),
]


def _utc_now() -> datetime:
    return datetime.now(UTC)


def _normalize_datetime(value: datetime) -> datetime:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("timestamps must include timezone information")
    return value.astimezone(UTC)


def _validate_json_value(value: Any, path: str = "value") -> None:
    """Reject values that cannot be represented safely in JSON."""

    if value is None or isinstance(value, str | int | bool):
        return
    if isinstance(value, float):
        if not isfinite(value):
            raise ValueError(f"{path} contains a non-finite number")
        return
    if isinstance(value, list):
        for index, item in enumerate(value):
            _validate_json_value(item, f"{path}[{index}]")
        return
    if isinstance(value, dict):
        for key, item in value.items():
            if not isinstance(key, str):
                raise TypeError(f"{path} must use string keys")
            _validate_json_value(item, f"{path}.{key}")
        return
    raise ValueError(f"{path} contains a non-JSON value of type {type(value).__name__}")


class SecurityModel(BaseModel):
    """Strict base configuration shared by all public domain models."""

    model_config = ConfigDict(
        extra="forbid",
        str_strip_whitespace=True,
        validate_assignment=True,
        validate_default=True,
    )


class CloudAccount(SecurityModel):
    """An AWS account or Azure subscription within governance scope."""

    account_id: Identifier
    provider: CloudProvider
    display_name: ShortText
    tenant_id: UUID | None = None
    enabled: bool = True
    metadata: dict[str, Any] = Field(default_factory=dict)

    @field_validator("metadata")
    @classmethod
    def validate_metadata(cls, value: dict[str, Any]) -> dict[str, Any]:
        _validate_json_value(value, "metadata")
        return value

    @model_validator(mode="after")
    def validate_provider_identifiers(self) -> Self:
        if self.provider is CloudProvider.AWS:
            if not re.fullmatch(r"\d{12}", self.account_id):
                raise ValueError("AWS account_id must contain exactly 12 digits")
            if self.tenant_id is not None:
                raise ValueError("tenant_id is only valid for Azure accounts")
        elif self.tenant_id is None:
            raise ValueError("tenant_id is required for Azure accounts")
        try:
            UUID(self.account_id)
        except ValueError as exc:
            if self.provider is CloudProvider.AZURE:
                raise ValueError("Azure account_id must be a valid subscription UUID") from exc
        return self


class Resource(SecurityModel):
    """A cloud resource evaluated during a compliance scan."""

    resource_id: ResourceIdentifier
    provider: CloudProvider
    account_id: Identifier
    resource_type: Identifier
    name: ShortText
    region: Region | None = None
    tags: dict[str, str] = Field(default_factory=dict)
    metadata: dict[str, Any] = Field(default_factory=dict)

    @field_validator("tags")
    @classmethod
    def validate_tags(cls, value: dict[str, str]) -> dict[str, str]:
        normalized: dict[str, str] = {}
        for key, tag_value in value.items():
            normalized_key = key.strip()
            if not normalized_key:
                raise ValueError("tag keys must not be empty")
            if len(normalized_key) > 256 or len(tag_value) > 256:
                raise ValueError("tag keys and values must be at most 256 characters")
            normalized[normalized_key] = tag_value.strip()
        return normalized

    @field_validator("metadata")
    @classmethod
    def validate_metadata(cls, value: dict[str, Any]) -> dict[str, Any]:
        _validate_json_value(value, "metadata")
        return value


class ComplianceRule(SecurityModel):
    """A security or IAM control evaluated against cloud resources."""

    rule_id: Identifier
    provider: CloudProvider
    service: Identifier
    title: ShortText
    description: LongText
    severity: Severity
    frameworks: list[ShortText] = Field(default_factory=list, max_length=100)
    remediation_guidance: LongText | None = None
    enabled: bool = True

    @field_validator("frameworks")
    @classmethod
    def frameworks_must_be_unique(cls, value: list[str]) -> list[str]:
        normalized = [framework.casefold() for framework in value]
        if len(normalized) != len(set(normalized)):
            raise ValueError("frameworks must not contain duplicates")
        return value


class Finding(SecurityModel):
    """A compliance rule violation associated with one cloud resource."""

    finding_id: UUID = Field(default_factory=uuid4)
    rule_id: Identifier
    resource: Resource
    title: ShortText
    description: LongText
    severity: Severity
    status: FindingStatus = FindingStatus.OPEN
    evidence: dict[str, Any] = Field(default_factory=dict)
    detected_at: datetime = Field(default_factory=_utc_now)
    updated_at: datetime | None = None
    due_at: datetime | None = None

    @field_validator("evidence")
    @classmethod
    def validate_evidence(cls, value: dict[str, Any]) -> dict[str, Any]:
        _validate_json_value(value, "evidence")
        return value

    @field_validator("detected_at", "updated_at", "due_at")
    @classmethod
    def timestamps_must_be_aware(cls, value: datetime | None) -> datetime | None:
        return None if value is None else _normalize_datetime(value)

    @model_validator(mode="after")
    def validate_timeline(self) -> Self:
        if self.updated_at is not None and self.updated_at < self.detected_at:
            raise ValueError("updated_at must not precede detected_at")
        if self.due_at is not None and self.due_at < self.detected_at:
            raise ValueError("due_at must not precede detected_at")
        return self


class RemediationAction(SecurityModel):
    """A tracked action intended to resolve a security finding."""

    action_id: UUID = Field(default_factory=uuid4)
    finding_id: UUID
    action_type: Identifier
    description: LongText
    status: RemediationStatus = RemediationStatus.PENDING
    created_at: datetime = Field(default_factory=_utc_now)
    updated_at: datetime | None = None
    started_at: datetime | None = None
    completed_at: datetime | None = None
    error_message: LongText | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)

    @field_validator("created_at", "updated_at", "started_at", "completed_at")
    @classmethod
    def timestamps_must_be_aware(cls, value: datetime | None) -> datetime | None:
        return None if value is None else _normalize_datetime(value)

    @field_validator("metadata")
    @classmethod
    def validate_metadata(cls, value: dict[str, Any]) -> dict[str, Any]:
        _validate_json_value(value, "metadata")
        return value

    @model_validator(mode="after")
    def validate_lifecycle(self) -> Self:
        for field_name in ("updated_at", "started_at", "completed_at"):
            value = getattr(self, field_name)
            if value is not None and value < self.created_at:
                raise ValueError(f"{field_name} must not precede created_at")
        if (
            self.started_at is not None
            and self.completed_at is not None
            and self.completed_at < self.started_at
        ):
            raise ValueError("completed_at must not precede started_at")
        if self.status is RemediationStatus.IN_PROGRESS and self.started_at is None:
            raise ValueError("started_at is required for an in-progress remediation")
        if self.status is RemediationStatus.COMPLETED and self.completed_at is None:
            raise ValueError("completed_at is required for a completed remediation")
        if self.status is RemediationStatus.FAILED and self.error_message is None:
            raise ValueError("error_message is required for a failed remediation")
        if self.status is not RemediationStatus.FAILED and self.error_message is not None:
            raise ValueError("error_message is only valid for a failed remediation")
        return self


class ScanResult(SecurityModel):
    """Complete output of a provider-neutral account compliance scan."""

    scan_id: UUID = Field(default_factory=uuid4)
    account: CloudAccount
    started_at: datetime
    completed_at: datetime
    resources_scanned: int = Field(ge=0)
    findings: list[Finding] = Field(default_factory=list)
    errors: list[ShortText] = Field(default_factory=list, max_length=1_000)

    @field_validator("started_at", "completed_at")
    @classmethod
    def timestamps_must_be_aware(cls, value: datetime) -> datetime:
        return _normalize_datetime(value)

    @model_validator(mode="after")
    def validate_result_consistency(self) -> Self:
        if self.completed_at < self.started_at:
            raise ValueError("completed_at must not precede started_at")

        resource_ids: set[str] = set()
        for finding in self.findings:
            resource = finding.resource
            if resource.provider is not self.account.provider:
                raise ValueError("finding resource provider must match the scanned account")
            if resource.account_id != self.account.account_id:
                raise ValueError("finding resource account_id must match the scanned account")
            resource_ids.add(resource.resource_id)

        if len(resource_ids) > self.resources_scanned:
            raise ValueError("resources_scanned cannot be less than resources represented by findings")
        return self
