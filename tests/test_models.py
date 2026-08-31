"""Tests for security domain model validation and serialization."""

from datetime import UTC, datetime, timedelta
from uuid import UUID, uuid4

import pytest
from pydantic import ValidationError

from cloud_security_governance.models import (
    CloudAccount,
    CloudProvider,
    ComplianceRule,
    Finding,
    FindingStatus,
    RemediationAction,
    RemediationStatus,
    Resource,
    ScanResult,
    Severity,
)

NOW = datetime(2026, 1, 15, 12, 0, tzinfo=UTC)
AZURE_SUBSCRIPTION_ID = "11111111-1111-4111-8111-111111111111"
AZURE_TENANT_ID = UUID("22222222-2222-4222-8222-222222222222")


@pytest.fixture
def aws_account() -> CloudAccount:
    return CloudAccount(
        account_id="123456789012",
        provider=CloudProvider.AWS,
        display_name="Production AWS",
        metadata={"owner": "security", "business_critical": True},
    )


@pytest.fixture
def aws_resource() -> Resource:
    return Resource(
        resource_id="arn:aws:s3:::example-audit-bucket",
        provider=CloudProvider.AWS,
        account_id="123456789012",
        resource_type="AWS::S3::Bucket",
        name="example-audit-bucket",
        region="us-east-1",
        tags={"Environment": "production"},
        metadata={"versioning": {"enabled": False}},
    )


@pytest.fixture
def compliance_rule() -> ComplianceRule:
    return ComplianceRule(
        rule_id="aws.s3.versioning-enabled",
        provider=CloudProvider.AWS,
        service="s3",
        title="S3 bucket versioning must be enabled",
        description="Checks whether an S3 bucket has object versioning enabled.",
        severity=Severity.HIGH,
        frameworks=["CIS AWS 1.5", "NIST CSF"],
        remediation_guidance="Enable versioning after reviewing retention requirements.",
    )


@pytest.fixture
def finding(aws_resource: Resource, compliance_rule: ComplianceRule) -> Finding:
    return Finding(
        finding_id=UUID("33333333-3333-4333-8333-333333333333"),
        rule_id=compliance_rule.rule_id,
        resource=aws_resource,
        title=compliance_rule.title,
        description="Versioning is disabled for the bucket.",
        severity=compliance_rule.severity,
        evidence={"versioning_status": None, "checked_properties": ["Status"]},
        detected_at=NOW,
        due_at=NOW + timedelta(days=30),
    )


def test_enums_are_json_compatible_strings() -> None:
    assert CloudProvider.AWS == "aws"
    assert Severity.CRITICAL.value == "critical"
    assert FindingStatus.RESOLVED.value == "resolved"
    assert RemediationStatus.IN_PROGRESS.value == "in_progress"


@pytest.mark.parametrize(
    ("model", "model_type"),
    [
        (
            CloudAccount(
                account_id=AZURE_SUBSCRIPTION_ID,
                provider="azure",
                display_name="Azure Production",
                tenant_id=AZURE_TENANT_ID,
            ),
            CloudAccount,
        ),
        (
            Resource(
                resource_id="/subscriptions/example/resourceGroups/security",
                provider="azure",
                account_id=AZURE_SUBSCRIPTION_ID,
                resource_type="Microsoft.Storage/storageAccounts",
                name="auditstorage",
            ),
            Resource,
        ),
        (
            ComplianceRule(
                rule_id="azure.storage.secure-transfer",
                provider="azure",
                service="storage",
                title="Secure transfer is required",
                description="Requires HTTPS for all storage account traffic.",
                severity="high",
            ),
            ComplianceRule,
        ),
    ],
)
def test_models_round_trip_through_json(model: object, model_type: type) -> None:
    encoded = model.model_dump_json()
    restored = model_type.model_validate_json(encoded)

    assert restored == model


def test_finding_and_nested_resource_round_trip(finding: Finding) -> None:
    restored = Finding.model_validate_json(finding.model_dump_json())

    assert restored == finding
    assert restored.resource.provider is CloudProvider.AWS
    assert restored.detected_at.tzinfo is not None


def test_scan_result_round_trip(
    aws_account: CloudAccount, finding: Finding
) -> None:
    result = ScanResult(
        account=aws_account,
        started_at=NOW,
        completed_at=NOW + timedelta(seconds=12),
        resources_scanned=4,
        findings=[finding],
    )

    restored = ScanResult.model_validate_json(result.model_dump_json())

    assert restored == result
    assert restored.resources_scanned == 4


def test_remediation_round_trip(finding: Finding) -> None:
    remediation = RemediationAction(
        finding_id=finding.finding_id,
        action_type="enable_versioning",
        description="Enable versioning on the affected bucket.",
        status=RemediationStatus.COMPLETED,
        created_at=NOW,
        started_at=NOW + timedelta(minutes=1),
        completed_at=NOW + timedelta(minutes=2),
        updated_at=NOW + timedelta(minutes=2),
        metadata={"automated": False},
    )

    restored = RemediationAction.model_validate_json(remediation.model_dump_json())

    assert restored == remediation
    assert isinstance(restored.action_id, UUID)


def test_default_identifiers_are_unique(aws_resource: Resource) -> None:
    values = {
        Finding(
            rule_id="aws.test.rule",
            resource=aws_resource,
            title="Example finding",
            description="Example finding used to verify unique identifiers.",
            severity=Severity.LOW,
        ).finding_id
        for _ in range(2)
    }

    assert len(values) == 2


def test_extra_fields_are_rejected(aws_account: CloudAccount) -> None:
    payload = aws_account.model_dump()
    payload["access_key"] = "must-not-be-accepted"

    with pytest.raises(ValidationError, match="Extra inputs are not permitted"):
        CloudAccount.model_validate(payload)


@pytest.mark.parametrize("account_id", ["123", "abcdefghijkl", "1234567890123"])
def test_aws_account_id_requires_twelve_digits(account_id: str) -> None:
    with pytest.raises(ValidationError, match="exactly 12 digits"):
        CloudAccount(account_id=account_id, provider="aws", display_name="Invalid AWS")


def test_azure_account_requires_subscription_uuid_and_tenant() -> None:
    with pytest.raises(ValidationError, match="tenant_id is required"):
        CloudAccount(
            account_id=AZURE_SUBSCRIPTION_ID,
            provider="azure",
            display_name="Missing tenant",
        )

    with pytest.raises(ValidationError, match="subscription UUID"):
        CloudAccount(
            account_id="not-a-subscription",
            provider="azure",
            display_name="Invalid Azure",
            tenant_id=AZURE_TENANT_ID,
        )


def test_resource_normalizes_tags_and_rejects_empty_keys() -> None:
    resource = Resource(
        resource_id="bucket-1",
        provider="aws",
        account_id="123456789012",
        resource_type="s3-bucket",
        name="bucket-1",
        tags={" Environment ": " production "},
    )
    assert resource.tags == {"Environment": "production"}

    with pytest.raises(ValidationError, match="tag keys must not be empty"):
        Resource(
            resource_id="bucket-1",
            provider="aws",
            account_id="123456789012",
            resource_type="s3-bucket",
            name="bucket-1",
            tags={" ": "value"},
        )


def test_metadata_and_evidence_reject_non_json_values(aws_resource: Resource) -> None:
    with pytest.raises(ValidationError, match="non-JSON value"):
        Resource(**{**aws_resource.model_dump(), "metadata": {"object": object()}})

    with pytest.raises(ValidationError, match="non-JSON value"):
        Finding(
            rule_id="aws.test.rule",
            resource=aws_resource,
            title="Invalid evidence",
            description="Evidence contains an unsupported Python object.",
            severity="low",
            evidence={"object": object()},
        )


@pytest.mark.parametrize("value", [float("nan"), float("inf"), float("-inf")])
def test_metadata_rejects_non_finite_numbers(value: float) -> None:
    with pytest.raises(ValidationError, match="non-finite number"):
        Resource(
            resource_id="bucket-1",
            provider="aws",
            account_id="123456789012",
            resource_type="s3-bucket",
            name="bucket-1",
            metadata={"invalid_number": value},
        )


def test_frameworks_are_case_insensitively_unique() -> None:
    with pytest.raises(ValidationError, match="must not contain duplicates"):
        ComplianceRule(
            rule_id="aws.test.rule",
            provider="aws",
            service="iam",
            title="Example rule",
            description="Example compliance rule with duplicate frameworks.",
            severity="medium",
            frameworks=["NIST CSF", "nist csf"],
        )


def test_naive_timestamps_are_rejected(aws_resource: Resource) -> None:
    with pytest.raises(ValidationError, match="timezone information"):
        Finding(
            rule_id="aws.test.rule",
            resource=aws_resource,
            title="Naive time",
            description="Finding with a timestamp that has no timezone.",
            severity="low",
            detected_at=datetime(2026, 1, 15, 12, 0),  # noqa: DTZ001
        )


def test_finding_timeline_must_be_ordered(aws_resource: Resource) -> None:
    with pytest.raises(ValidationError, match="updated_at must not precede detected_at"):
        Finding(
            rule_id="aws.test.rule",
            resource=aws_resource,
            title="Invalid timeline",
            description="Finding update time predates its detection time.",
            severity="medium",
            detected_at=NOW,
            updated_at=NOW - timedelta(seconds=1),
        )


@pytest.mark.parametrize(
    ("status", "kwargs", "message"),
    [
        (RemediationStatus.IN_PROGRESS, {}, "started_at is required"),
        (RemediationStatus.COMPLETED, {}, "completed_at is required"),
        (RemediationStatus.FAILED, {}, "error_message is required"),
        (
            RemediationStatus.PENDING,
            {"error_message": "Unexpected"},
            "error_message is only valid",
        ),
    ],
)
def test_remediation_status_requires_consistent_fields(
    status: RemediationStatus, kwargs: dict[str, object], message: str
) -> None:
    with pytest.raises(ValidationError, match=message):
        RemediationAction(
            finding_id=uuid4(),
            action_type="manual_review",
            description="Review the finding before making a cloud change.",
            status=status,
            created_at=NOW,
            **kwargs,
        )


def test_scan_result_rejects_provider_mismatch(
    aws_account: CloudAccount, finding: Finding
) -> None:
    azure_resource = Resource(
        resource_id="/subscriptions/example/resourceGroups/security",
        provider="azure",
        account_id=AZURE_SUBSCRIPTION_ID,
        resource_type="Microsoft.Storage/storageAccounts",
        name="auditstorage",
    )
    mismatched_finding = finding.model_copy(update={"resource": azure_resource})

    with pytest.raises(ValidationError, match="provider must match"):
        ScanResult(
            account=aws_account,
            started_at=NOW,
            completed_at=NOW + timedelta(seconds=1),
            resources_scanned=1,
            findings=[mismatched_finding],
        )


def test_scan_result_rejects_inconsistent_resource_count(
    aws_account: CloudAccount, finding: Finding
) -> None:
    with pytest.raises(ValidationError, match="resources_scanned cannot be less"):
        ScanResult(
            account=aws_account,
            started_at=NOW,
            completed_at=NOW + timedelta(seconds=1),
            resources_scanned=0,
            findings=[finding],
        )
