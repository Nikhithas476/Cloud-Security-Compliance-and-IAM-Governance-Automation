"""Tests for provider-neutral scanner abstraction and multi-cloud orchestration."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from unittest.mock import MagicMock
from uuid import UUID

import pytest

from cloud_security_governance import BaseScanner, ScannerOrchestrator
from cloud_security_governance.aws import AWSScanner
from cloud_security_governance.azure import AzureScanner
from cloud_security_governance.exceptions import AWSScanError, ConfigurationError
from cloud_security_governance.models import (
    CloudAccount,
    CloudProvider,
    Finding,
    MultiCloudScanResult,
    Resource,
    ScanResult,
    Severity,
)

NOW = datetime(2026, 9, 18, 12, 0, tzinfo=UTC)
AWS_ACCOUNT_ID = "123456789012"
AZURE_SUBSCRIPTION_ID = "11111111-1111-4111-8111-111111111111"
AZURE_TENANT_ID = UUID("22222222-2222-4222-8222-222222222222")


class StubScanner(BaseScanner):
    def __init__(
        self,
        provider: CloudProvider,
        result: ScanResult | None = None,
        error: Exception | None = None,
    ) -> None:
        self.provider = provider
        self._result = result
        self._error = error
        self.call_count = 0

    def scan(self) -> ScanResult:
        self.call_count += 1
        if self._error is not None:
            raise self._error
        assert self._result is not None
        return self._result


def cloud_result(provider: CloudProvider) -> ScanResult:
    if provider is CloudProvider.AWS:
        account = CloudAccount(
            account_id=AWS_ACCOUNT_ID,
            provider=provider,
            display_name="AWS test account",
        )
        resource = Resource(
            resource_id="arn:aws:s3:::test-bucket",
            provider=provider,
            account_id=AWS_ACCOUNT_ID,
            resource_type="s3-bucket",
            name="test-bucket",
        )
        rule_id = "aws.s3.bucket.encryption-enabled"
    else:
        account = CloudAccount(
            account_id=AZURE_SUBSCRIPTION_ID,
            provider=provider,
            display_name="Azure test subscription",
            tenant_id=AZURE_TENANT_ID,
        )
        resource = Resource(
            resource_id=(
                f"/subscriptions/{AZURE_SUBSCRIPTION_ID}/resourceGroups/test/"
                "providers/Microsoft.Storage/storageAccounts/teststorage"
            ),
            provider=provider,
            account_id=AZURE_SUBSCRIPTION_ID,
            resource_type="Microsoft.Storage/storageAccounts",
            name="teststorage",
        )
        rule_id = "azure.storage.encryption.service-enabled"
    finding = Finding(
        rule_id=rule_id,
        resource=resource,
        title="Test security finding",
        description="A mocked cloud resource violates a security control.",
        severity=Severity.HIGH,
        detected_at=NOW,
    )
    return ScanResult(
        account=account,
        started_at=NOW,
        completed_at=NOW + timedelta(seconds=1),
        resources_scanned=1,
        findings=[finding],
    )


def orchestrator(*scanners: BaseScanner) -> ScannerOrchestrator:
    return ScannerOrchestrator(
        scanners,
        clock=MagicMock(side_effect=[NOW, NOW + timedelta(seconds=3)]),
    )


def test_aws_and_azure_scanners_implement_base_scanner() -> None:
    assert issubclass(AWSScanner, BaseScanner)
    assert issubclass(AzureScanner, BaseScanner)
    assert AWSScanner.provider is CloudProvider.AWS
    assert AzureScanner.provider is CloudProvider.AZURE


def test_aws_only_scanning() -> None:
    aws = StubScanner(CloudProvider.AWS, cloud_result(CloudProvider.AWS))

    result = orchestrator(aws).scan()

    assert isinstance(result, MultiCloudScanResult)
    assert [item.account.provider for item in result.results] == [CloudProvider.AWS]
    assert result.findings == result.results[0].findings
    assert result.resources_scanned == 1
    assert result.findings_count == 1
    assert result.failures == []
    assert result.duration_seconds == 3.0
    assert aws.call_count == 1


def test_azure_only_scanning() -> None:
    azure = StubScanner(CloudProvider.AZURE, cloud_result(CloudProvider.AZURE))

    result = orchestrator(azure).scan()

    assert [item.account.provider for item in result.results] == [CloudProvider.AZURE]
    assert result.findings[0].resource.provider is CloudProvider.AZURE
    assert result.resources_scanned == 1
    assert result.failures == []
    assert azure.call_count == 1


def test_multi_cloud_scanning_combines_findings_and_metadata() -> None:
    aws = StubScanner(CloudProvider.AWS, cloud_result(CloudProvider.AWS))
    azure = StubScanner(CloudProvider.AZURE, cloud_result(CloudProvider.AZURE))

    result = orchestrator(aws, azure).scan()

    assert [item.account.provider for item in result.results] == [
        CloudProvider.AWS,
        CloudProvider.AZURE,
    ]
    assert [finding.resource.provider for finding in result.findings] == [
        CloudProvider.AWS,
        CloudProvider.AZURE,
    ]
    assert result.resources_scanned == 2
    assert result.findings_count == 2
    assert result.failures == []
    restored = MultiCloudScanResult.model_validate_json(result.model_dump_json())
    assert restored == result


def test_partial_cloud_failure_preserves_other_cloud_findings() -> None:
    aws = StubScanner(
        CloudProvider.AWS,
        error=AWSScanError("AWS security scan could not be completed"),
    )
    azure = StubScanner(CloudProvider.AZURE, cloud_result(CloudProvider.AZURE))

    result = orchestrator(aws, azure).scan()

    assert [item.account.provider for item in result.results] == [CloudProvider.AZURE]
    assert result.findings == result.results[0].findings
    assert result.resources_scanned == 1
    assert result.findings_count == 1
    assert len(result.failures) == 1
    assert result.failures[0].provider is CloudProvider.AWS
    assert result.failures[0].error_type == "AWSScanError"
    assert result.failures[0].message == "AWS security scan could not be completed"
    assert aws.call_count == 1
    assert azure.call_count == 1


def test_unexpected_programming_error_is_not_silenced() -> None:
    aws = StubScanner(CloudProvider.AWS, error=RuntimeError("programming defect"))

    with pytest.raises(RuntimeError, match="programming defect"):
        orchestrator(aws).scan()


def test_duplicate_or_empty_scanner_configuration_is_rejected() -> None:
    with pytest.raises(ConfigurationError, match="At least one"):
        ScannerOrchestrator([])

    aws = StubScanner(CloudProvider.AWS, cloud_result(CloudProvider.AWS))
    with pytest.raises(ConfigurationError, match="one scanner per"):
        ScannerOrchestrator([aws, aws])
