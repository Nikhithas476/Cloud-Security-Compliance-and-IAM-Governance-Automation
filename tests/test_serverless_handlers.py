import importlib.util
import json
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock
from uuid import uuid4

from cloud_security_governance.models import CloudProvider, Finding, Resource, Severity
from cloud_security_governance.remediation import RemediationOutcome

ROOT = Path(__file__).parents[1]


def load(name: str, relative_path: str):
    spec = importlib.util.spec_from_file_location(name, ROOT / relative_path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def finding_payload() -> dict:
    item = Finding(
        rule_id="aws.iam.stale-key",
        resource=Resource(
            resource_id="arn:aws:iam::123456789012:user/alice",
            provider=CloudProvider.AWS,
            account_id="123456789012",
            resource_type="iam-user",
            name="alice",
        ),
        title="Stale key",
        description="An old key exists.",
        severity=Severity.HIGH,
        remediation_available=True,
    )
    return item.model_dump(mode="json")


def workflow_result():
    return SimpleNamespace(
        scan=SimpleNamespace(scan_id=uuid4(), findings=[object()]),
        risk=SimpleNamespace(overall_risk_score=8.0),
        reports=SimpleNamespace(json_report="{}", csv_report="", html_report=""),
    )


def remediation_result(*, dry_run: bool = False):
    return SimpleNamespace(
        finding_id=uuid4(),
        executed=not dry_run,
        dry_run=dry_run,
        model_dump=lambda mode: {
            "outcome": (
                RemediationOutcome.DRY_RUN.value if dry_run else RemediationOutcome.SUCCEEDED.value
            )
        },
    )


def test_lambda_scan_handler_runs_existing_workflow() -> None:
    module = load("lambda_scan_handler", "lambda/scan_handler.py")
    workflow = Mock()
    workflow.run.return_value = workflow_result()
    module.configure_workflow(lambda: workflow)
    response = module.lambda_handler({}, None)
    assert response["statusCode"] == 200
    assert json.loads(response["body"])["findings_count"] == 1
    workflow.run.assert_called_once_with()


def test_lambda_remediation_rejects_unapproved_request_before_engine() -> None:
    module = load("lambda_remediation_handler", "lambda/remediation_handler.py")
    engine = Mock()
    module.configure_engine(lambda: engine)
    response = module.lambda_handler(
        {
            "finding": finding_payload(),
            "action": "aws.iam.disable-stale-access-key",
            "actor": "operator",
            "parameters": {},
        },
        None,
    )
    assert response["statusCode"] == 403
    engine.remediate.assert_not_called()


def test_lambda_remediation_passes_approved_request_to_engine() -> None:
    module = load("lambda_remediation_handler_approved", "lambda/remediation_handler.py")
    engine = Mock()
    engine.remediate.return_value = remediation_result()
    module.configure_engine(lambda: engine)
    response = module.lambda_handler(
        {
            "finding": finding_payload(),
            "action": "aws.iam.disable-stale-access-key",
            "actor": "operator",
            "parameters": {},
            "approval_id": str(uuid4()),
        },
        None,
    )
    assert response["statusCode"] == 200
    engine.remediate.assert_called_once()


def test_azure_scan_function_runs_existing_workflow() -> None:
    module = load("azure_scan_function", "azure_functions/scan_function.py")
    workflow = Mock()
    workflow.run.return_value = workflow_result()
    module.configure_workflow(lambda: workflow)
    response = module.main({})
    assert response["status_code"] == 200
    assert response["json"]["overall_risk_score"] == 8.0


def test_azure_remediation_requires_approval_but_allows_dry_run() -> None:
    module = load("azure_remediation_function", "azure_functions/remediation_function.py")
    engine = Mock()
    module.configure_engine(lambda: engine)
    body = {
        "finding": finding_payload(),
        "action": "aws.iam.disable-stale-access-key",
        "actor": "operator",
        "parameters": {},
    }
    assert module.main(body)["status_code"] == 403
    engine.remediate.assert_not_called()
    engine.remediate.return_value = remediation_result(dry_run=True)
    body["dry_run"] = True
    assert module.main(body)["status_code"] == 200
    engine.remediate.assert_called_once()


def test_handlers_return_sanitized_errors_when_unconfigured() -> None:
    lambda_module = load("unconfigured_lambda_scan", "lambda/scan_handler.py")
    azure_module = load("unconfigured_azure_scan", "azure_functions/scan_function.py")
    assert lambda_module.lambda_handler({}, None)["statusCode"] == 500
    assert azure_module.main({})["status_code"] == 500
