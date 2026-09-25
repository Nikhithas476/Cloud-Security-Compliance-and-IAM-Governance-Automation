from types import SimpleNamespace
from unittest.mock import Mock
from uuid import uuid4

import pytest
from fastapi.testclient import TestClient

from cloud_security_governance.auth import TokenAuthenticator
from cloud_security_governance.main import app, create_app
from cloud_security_governance.models import (
    CloudProvider,
    Finding,
    FindingStatus,
    Resource,
    Severity,
)
from cloud_security_governance.remediation import (
    ApprovalRequest,
    ApprovalStatus,
    RemediationOutcome,
    RemediationReview,
)

READER_TOKEN = "reader-secret-value-with-32-characters"
OPERATOR_TOKEN = "operator-secret-value-with-32-characters"
REVIEWER_TOKEN = "reviewer-secret-value-with-32-characters"


def test_health_endpoint() -> None:
    response = TestClient(app).get("/health")

    assert response.status_code == 200
    assert response.json()["status"] == "ok"
    assert response.json()["version"] == "0.1.0"


def test_production_service_factory_is_lazy_and_cached() -> None:
    service = Mock()
    service.list_findings.return_value = []
    factory = Mock(return_value=service)
    application = create_app(
        authenticator=TokenAuthenticator(READER_TOKEN, OPERATOR_TOKEN, REVIEWER_TOKEN),
        api_service_factory=factory,
    )
    client = TestClient(application)
    assert client.get("/health").status_code == 200
    assert factory.call_count == 0
    assert client.get("/findings", headers=_headers(READER_TOKEN)).status_code == 200
    assert client.get("/findings", headers=_headers(READER_TOKEN)).status_code == 200
    factory.assert_called_once_with()


def _finding() -> Finding:
    return Finding(
        rule_id="aws.test.rule",
        resource=Resource(
            resource_id="arn:aws:s3:::test",
            provider=CloudProvider.AWS,
            account_id="123456789012",
            resource_type="AWS::S3::Bucket",
            name="test",
            metadata={"password": "must-not-leak"},
        ),
        title="Test finding",
        description="A test issue.",
        severity=Severity.HIGH,
        remediation_available=True,
        evidence={"api_key": "must-not-leak"},
    )


def _client(service: Mock) -> TestClient:
    application = create_app(
        service, TokenAuthenticator(READER_TOKEN, OPERATOR_TOKEN, REVIEWER_TOKEN)
    )
    return TestClient(application, raise_server_exceptions=False)


def _headers(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


def test_protected_routes_require_authentication_and_roles() -> None:
    service = Mock()
    client = _client(service)
    assert client.get("/findings").status_code == 401
    assert client.post("/scans", headers=_headers(READER_TOKEN)).status_code == 403
    assert client.get("/findings", headers=_headers("wrong")).status_code == 401
    service.start_scan.assert_not_called()


def test_authenticator_rejects_weak_or_shared_tokens() -> None:
    with pytest.raises(ValueError, match="at least 32"):
        TokenAuthenticator("short", OPERATOR_TOKEN)
    with pytest.raises(ValueError, match="must be different"):
        TokenAuthenticator(READER_TOKEN, READER_TOKEN)


def test_approval_api_enforces_separation_of_duties() -> None:
    service = Mock()
    finding_id = uuid4()
    pending = ApprovalRequest(
        finding_id=finding_id,
        action="aws.test.action",
        request_fingerprint="a" * 64,
        requested_by="api-operator",
    )
    service.request_approval.return_value = RemediationReview(
        finding_id=finding_id, action=pending.action, previous_state={}, approval=pending
    )
    service.approve.return_value = pending.model_copy(
        update={
            "status": ApprovalStatus.APPROVED,
            "reviewed_by": "api-reviewer",
            "reviewed_at": pending.requested_at,
        }
    )
    client = _client(service)
    created = client.post(
        f"/approvals/{finding_id}",
        json={"action": pending.action, "parameters": {}},
        headers=_headers(OPERATOR_TOKEN),
    )
    assert created.status_code == 200
    approval_id = created.json()["approval_id"]
    assert (
        client.post(
            f"/approvals/{approval_id}/approve",
            json={},
            headers=_headers(OPERATOR_TOKEN),
        ).status_code
        == 403
    )
    approved = client.post(
        f"/approvals/{approval_id}/approve",
        json={"notes": "SEC-42"},
        headers=_headers(REVIEWER_TOKEN),
    )
    assert approved.status_code == 200
    assert approved.json()["status"] == "approved"
    assert "request_fingerprint" not in approved.text


def test_scan_endpoints_delegate_to_service() -> None:
    service = Mock()
    scan_id = uuid4()
    scan = SimpleNamespace(scan_id=scan_id, resources_scanned=2, findings=[_finding()], failures=[])
    service.start_scan.return_value = SimpleNamespace(scan=scan)
    service.get_scan.return_value = scan
    client = _client(service)
    started = client.post("/scans", headers=_headers(OPERATOR_TOKEN))
    fetched = client.get(f"/scans/{scan_id}", headers=_headers(READER_TOKEN))
    assert started.status_code == 200
    assert fetched.json()["findings_count"] == 1


def test_findings_are_validated_filtered_and_redacted() -> None:
    service = Mock()
    service.list_findings.return_value = [_finding()]
    service.get_finding.return_value = _finding()
    client = _client(service)
    response = client.get(
        "/findings?provider=aws&status=open&limit=10", headers=_headers(READER_TOKEN)
    )
    assert response.status_code == 200
    serialized = response.text
    assert "must-not-leak" not in serialized
    service.list_findings.assert_called_once_with(
        provider=CloudProvider.AWS, status=FindingStatus.OPEN, limit=10
    )
    assert client.get("/findings?limit=501", headers=_headers(READER_TOKEN)).status_code == 422


def test_get_missing_records_returns_404() -> None:
    service = Mock()
    service.get_finding.return_value = None
    service.get_scan.return_value = None
    service.get_reports.return_value = None
    client = _client(service)
    headers = _headers(READER_TOKEN)
    assert client.get(f"/findings/{uuid4()}", headers=headers).status_code == 404
    assert client.get(f"/scans/{uuid4()}", headers=headers).status_code == 404
    assert client.get(f"/reports/{uuid4()}", headers=headers).status_code == 404


def test_reports_are_returned_from_service() -> None:
    service = Mock()
    service.get_reports.return_value = {"json": "{}", "csv": "x", "html": "<p>x</p>"}
    response = _client(service).get(f"/reports/{uuid4()}", headers=_headers(READER_TOKEN))
    assert response.status_code == 200
    assert response.json()["json"] == "{}"


def test_remediation_requires_operator_and_explicit_approval() -> None:
    service = Mock()
    finding_id = uuid4()
    client = _client(service)
    body = {"action": "aws.iam.disable-stale-access-key", "parameters": {}}
    assert (
        client.post(
            f"/remediation/{finding_id}", json=body, headers=_headers(READER_TOKEN)
        ).status_code
        == 403
    )
    assert (
        client.post(
            f"/remediation/{finding_id}", json=body, headers=_headers(OPERATOR_TOKEN)
        ).status_code
        == 403
    )
    service.remediate.assert_not_called()


def test_approved_remediation_uses_authenticated_actor() -> None:
    service = Mock()
    finding_id = uuid4()
    service.remediate.return_value = SimpleNamespace(
        finding_id=finding_id,
        action="aws.test.action",
        outcome=RemediationOutcome.SUCCEEDED,
        executed=True,
        verified=True,
        message="done",
    )
    approval_id = uuid4()
    response = _client(service).post(
        f"/remediation/{finding_id}",
        json={"action": "aws.test.action", "parameters": {}, "approval_id": str(approval_id)},
        headers=_headers(OPERATOR_TOKEN),
    )
    assert response.status_code == 200
    assert service.remediate.call_args.kwargs["actor"] == "api-operator"


def test_remediation_rejects_extra_fields_and_hides_internal_errors() -> None:
    service = Mock()
    client = _client(service)
    finding_id = uuid4()
    invalid = client.post(
        f"/remediation/{finding_id}",
        json={"action": "aws.test.action", "dry_run": True, "secret": "x"},
        headers=_headers(OPERATOR_TOKEN),
    )
    assert invalid.status_code == 422
    service.list_findings.side_effect = RuntimeError("database password secret")
    response = client.get("/findings", headers=_headers(READER_TOKEN))
    assert response.status_code == 500
    assert "database password" not in response.text
