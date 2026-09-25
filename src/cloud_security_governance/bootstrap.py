"""Production service composition for API and serverless entry points."""

from __future__ import annotations

import os
from dataclasses import dataclass
from functools import lru_cache

from azure.mgmt.authorization import AuthorizationManagementClient

from cloud_security_governance.api_service import GovernanceAPIService
from cloud_security_governance.aws import AWSScanner
from cloud_security_governance.azure import AzureScanner, AzureStorageEncryptionRules
from cloud_security_governance.compliance_engine import ComplianceEngine
from cloud_security_governance.config import get_settings
from cloud_security_governance.exceptions import ConfigurationError
from cloud_security_governance.models import CloudProvider, Severity
from cloud_security_governance.notifications import WebhookNotifier
from cloud_security_governance.orchestrator import ScannerOrchestrator
from cloud_security_governance.remediation import (
    ApprovalService,
    RemediationEngine,
    StorageAuditSink,
)
from cloud_security_governance.remediation.aws import (
    DisableStaleAccessKeyExecutor,
    RemovePolicyPermissionExecutor,
)
from cloud_security_governance.remediation.azure import RemoveRBACAssignmentExecutor
from cloud_security_governance.reports import ComplianceReportGenerator
from cloud_security_governance.risk import RiskCalculator
from cloud_security_governance.storage import AzureBlobStorage, DynamoDBStorage, FindingStorage
from cloud_security_governance.workflow import ComplianceWorkflowService


@dataclass(frozen=True)
class ApplicationRuntime:
    api: GovernanceAPIService
    workflow: ComplianceWorkflowService
    remediation: RemediationEngine
    storage: FindingStorage


def _providers() -> tuple[CloudProvider, ...]:
    raw = os.getenv("CLOUD_PROVIDERS")
    if raw is None:
        raw = "aws,azure" if os.getenv("AZURE_SUBSCRIPTION_ID") else "aws"
    try:
        providers = tuple(
            CloudProvider(item.strip().casefold()) for item in raw.split(",") if item.strip()
        )
    except ValueError as exc:
        raise ConfigurationError("CLOUD_PROVIDERS must contain only aws and azure") from exc
    if not providers or len(providers) != len(set(providers)):
        raise ConfigurationError("CLOUD_PROVIDERS must contain unique configured providers")
    return providers


def _storage() -> FindingStorage:
    backend = os.getenv("STORAGE_BACKEND", "dynamodb").strip().casefold()
    if backend == "dynamodb":
        return DynamoDBStorage()
    if backend == "azure_blob":
        return AzureBlobStorage()
    raise ConfigurationError("STORAGE_BACKEND must be dynamodb or azure_blob")


@lru_cache
def get_runtime() -> ApplicationRuntime:
    """Build and cache one process-local runtime using environment configuration."""

    settings = get_settings()
    providers = _providers()
    storage = _storage()
    scanners = []
    executors = []

    if CloudProvider.AWS in providers:
        aws = AWSScanner(
            profile=settings.aws_profile,
            region=settings.aws_region,
            role_arn=settings.aws_role_arn,
            encryption_rule_ids=settings.aws_encryption_rules,
            config_rule_names=settings.aws_config_rule_names,
        )
        scanners.append(aws)
        iam = aws._session.client("iam", region_name=settings.aws_region)
        executors.extend([DisableStaleAccessKeyExecutor(iam), RemovePolicyPermissionExecutor(iam)])

    if CloudProvider.AZURE in providers:
        azure = AzureScanner(
            subscription_id=settings.azure_subscription_id,
            tenant_id=settings.azure_tenant_id,
            storage_encryption_rules=AzureStorageEncryptionRules.model_validate(
                settings.azure_storage_encryption_rules
            ),
        )
        scanners.append(azure)
        authorization = AuthorizationManagementClient(azure._credential, azure.subscription_id)
        executors.append(RemoveRBACAssignmentExecutor(authorization))

    orchestrator = ScannerOrchestrator(scanners)
    approvals = ApprovalService(repository=storage)
    remediation = RemediationEngine(approvals, executors, StorageAuditSink(storage))
    notifiers = []
    webhook = os.getenv("ALERT_WEBHOOK_URL")
    if webhook:
        notifiers.append(
            WebhookNotifier(
                webhook,
                alert_severities=(Severity.CRITICAL, Severity.HIGH),
            )
        )
    workflow = ComplianceWorkflowService(
        scanner=orchestrator,
        compliance_engine=ComplianceEngine(),
        risk_calculator=RiskCalculator(settings.risk_weights),
        storage=storage,
        report_generator=ComplianceReportGenerator(),
        notifiers=notifiers,
    )
    api = GovernanceAPIService(workflow, storage, remediation)
    return ApplicationRuntime(api=api, workflow=workflow, remediation=remediation, storage=storage)


def get_api_service() -> GovernanceAPIService:
    return get_runtime().api


def get_workflow_service() -> ComplianceWorkflowService:
    return get_runtime().workflow


def get_remediation_engine() -> RemediationEngine:
    return get_runtime().remediation
