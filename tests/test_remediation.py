from datetime import UTC, datetime
from unittest.mock import Mock

import pytest
from azure.core.exceptions import ResourceNotFoundError

from cloud_security_governance.exceptions import ApprovalError
from cloud_security_governance.models import CloudProvider, Finding, Resource, Severity
from cloud_security_governance.remediation import (
    ApprovalService,
    ApprovalStatus,
    InMemoryAuditSink,
    RemediationEngine,
    RemediationExecutor,
    RemediationOutcome,
    StorageAuditSink,
)
from cloud_security_governance.remediation.aws import (
    DISABLE_STALE_ACCESS_KEY,
    REMOVE_POLICY_PERMISSION,
    DisableStaleAccessKeyExecutor,
    RemovePolicyPermissionExecutor,
)
from cloud_security_governance.remediation.azure import (
    REMOVE_RBAC_ASSIGNMENT,
    RemoveRBACAssignmentExecutor,
)


def finding(provider: CloudProvider = CloudProvider.AWS) -> Finding:
    resource_id = (
        "arn:aws:iam::123456789012:user/alice"
        if provider is CloudProvider.AWS
        else "/subscriptions/11111111-1111-1111-1111-111111111111/providers/Microsoft.Authorization/roleAssignments/abc"
    )
    return Finding(
        rule_id="test.rule",
        resource=Resource(
            resource_id=resource_id,
            provider=provider,
            account_id=(
                "123456789012"
                if provider is CloudProvider.AWS
                else "11111111-1111-1111-1111-111111111111"
            ),
            resource_type="iam",
            name="target",
        ),
        title="Unsafe permission",
        description="A controlled remediation is available.",
        severity=Severity.HIGH,
        remediation_available=True,
    )


class FakeExecutor(RemediationExecutor):
    provider = CloudProvider.AWS
    action = "aws.test.action"

    def __init__(self, verified: bool = True, fail: bool = False) -> None:
        self.calls: list[str] = []
        self.verified = verified
        self.fail = fail

    def review(self, finding: Finding, parameters: dict) -> dict:
        self.calls.append("review")
        return {"enabled": True}

    def execute(self, finding: Finding, parameters: dict) -> dict:
        self.calls.append("execute")
        if self.fail:
            raise RuntimeError("provider detail")
        return {"enabled": False}

    def verify(self, finding: Finding, parameters: dict) -> tuple[bool, dict]:
        self.calls.append("verify")
        return self.verified, {"enabled": not self.verified}


def test_remediation_requires_explicit_approval_and_audits_attempt() -> None:
    executor = FakeExecutor()
    audit = InMemoryAuditSink()
    engine = RemediationEngine(ApprovalService(), [executor], audit)

    result = engine.remediate(finding(), executor.action, "operator", {})

    assert result.outcome is RemediationOutcome.NOT_APPROVED
    assert result.executed is False
    assert executor.calls == ["review"]
    assert audit.events[0].result is RemediationOutcome.NOT_APPROVED


def test_approved_remediation_follows_full_lifecycle_and_is_one_time() -> None:
    executor = FakeExecutor()
    approvals = ApprovalService()
    engine = RemediationEngine(approvals, [executor])
    item = finding()
    review = engine.review_and_request(item, executor.action, {"target": "x"}, "requester")
    approved = approvals.approve(review.approval.approval_id, "reviewer", "Ticket SEC-1")

    result = engine.remediate(
        item, executor.action, "operator", {"target": "x"}, approval_id=approved.approval_id
    )

    assert result.outcome is RemediationOutcome.SUCCEEDED
    assert result.approved and result.executed and result.verified
    assert executor.calls == ["review", "review", "execute", "verify"]
    replay = engine.remediate(
        item, executor.action, "operator", {"target": "x"}, approval_id=approved.approval_id
    )
    assert replay.outcome is RemediationOutcome.NOT_APPROVED


def test_approval_persists_and_prevents_self_approval() -> None:
    repository = Mock()
    first = ApprovalService(repository=repository)
    request = first.request(finding().finding_id, "aws.test.action", {}, "requester")
    repository.save_approval.assert_called_once_with(request)
    repository.get_approval.return_value = request
    second = ApprovalService(repository=repository)
    with pytest.raises(ApprovalError, match="cannot approve"):
        second.approve(request.approval_id, "requester")
    approved = second.approve(request.approval_id, "independent-reviewer")
    assert approved.status is ApprovalStatus.APPROVED


def test_dry_run_never_executes_or_requires_approval() -> None:
    executor = FakeExecutor()
    engine = RemediationEngine(ApprovalService(), [executor])
    result = engine.remediate(finding(), executor.action, "operator", {}, dry_run=True)
    assert result.outcome is RemediationOutcome.DRY_RUN
    assert executor.calls == ["review"]


def test_verification_failure_and_execution_failure_are_audited() -> None:
    for executor, expected in [
        (FakeExecutor(verified=False), RemediationOutcome.VERIFICATION_FAILED),
        (FakeExecutor(fail=True), RemediationOutcome.FAILED),
    ]:
        approvals = ApprovalService()
        audit = InMemoryAuditSink()
        engine = RemediationEngine(approvals, [executor], audit)
        item = finding()
        request = engine.review_and_request(item, executor.action, {}, "requester").approval
        approvals.approve(request.approval_id, "reviewer")
        result = engine.remediate(
            item, executor.action, "operator", {}, approval_id=request.approval_id
        )
        assert result.outcome is expected
        assert audit.events[-1].result is expected


def test_approval_is_bound_to_exact_parameters_and_rejection_is_final() -> None:
    approvals = ApprovalService()
    item = finding()
    request = approvals.request(item.finding_id, "aws.test.action", {"target": "a"}, "requester")
    rejected = approvals.reject(request.approval_id, "reviewer")
    assert rejected.status is ApprovalStatus.REJECTED
    with pytest.raises(ApprovalError):
        approvals.approve(request.approval_id, "reviewer")
    request = approvals.request(item.finding_id, "aws.test.action", {"target": "a"}, "requester")
    approvals.approve(request.approval_id, "reviewer")
    with pytest.raises(ApprovalError):
        approvals.consume(request.approval_id, item.finding_id, "aws.test.action", {"target": "b"})


def test_storage_audit_sink_preserves_complete_history() -> None:
    storage = Mock()
    sink = StorageAuditSink(storage)
    engine = RemediationEngine(ApprovalService(), [FakeExecutor()], sink)
    result = engine.remediate(finding(), "aws.test.action", "operator", {}, dry_run=True)
    assert result.outcome is RemediationOutcome.DRY_RUN
    saved = storage.save_remediation_history.call_args.args[0]
    assert saved.finding_id == result.finding_id
    assert saved.metadata["actor"] == "operator"
    assert saved.metadata["previous_state"] == {"enabled": True}
    assert saved.metadata["new_state"] == {}


def test_disable_access_key_executes_and_verifies() -> None:
    iam = Mock()
    iam.list_access_keys.side_effect = [
        {
            "AccessKeyMetadata": [
                {
                    "AccessKeyId": "AKIAOLD",
                    "Status": "Active",
                    "CreateDate": datetime(2020, 1, 1, tzinfo=UTC),
                }
            ]
        },
        {
            "AccessKeyMetadata": [
                {
                    "AccessKeyId": "AKIAOLD",
                    "Status": "Inactive",
                    "CreateDate": datetime(2020, 1, 1, tzinfo=UTC),
                }
            ]
        },
    ]
    executor = DisableStaleAccessKeyExecutor(iam)
    approvals = ApprovalService()
    engine = RemediationEngine(approvals, [executor])
    params = {"user_name": "alice", "access_key_id": "AKIAOLD"}
    request = engine.review_and_request(
        finding(), DISABLE_STALE_ACCESS_KEY, params, "requester"
    ).approval
    approvals.approve(request.approval_id, "reviewer")
    result = engine.remediate(
        finding(), DISABLE_STALE_ACCESS_KEY, "operator", params, approval_id=request.approval_id
    )
    # A different finding cannot consume the approval.
    assert result.outcome is RemediationOutcome.NOT_APPROVED
    iam.update_access_key.assert_not_called()


def test_disable_access_key_with_matching_finding() -> None:
    iam = Mock()
    iam.list_access_keys.side_effect = [
        {"AccessKeyMetadata": [{"AccessKeyId": "AKIAOLD", "Status": "Active"}]},
        {"AccessKeyMetadata": [{"AccessKeyId": "AKIAOLD", "Status": "Active"}]},
        {"AccessKeyMetadata": [{"AccessKeyId": "AKIAOLD", "Status": "Inactive"}]},
    ]
    item = finding()
    executor = DisableStaleAccessKeyExecutor(iam)
    approvals = ApprovalService()
    engine = RemediationEngine(approvals, [executor])
    params = {"user_name": "alice", "access_key_id": "AKIAOLD"}
    request = engine.review_and_request(
        item, DISABLE_STALE_ACCESS_KEY, params, "requester"
    ).approval
    approvals.approve(request.approval_id, "reviewer")
    result = engine.remediate(
        item, DISABLE_STALE_ACCESS_KEY, "operator", params, approval_id=request.approval_id
    )
    assert result.outcome is RemediationOutcome.SUCCEEDED
    iam.update_access_key.assert_called_once_with(
        UserName="alice", AccessKeyId="AKIAOLD", Status="Inactive"
    )


def test_remove_one_exact_policy_permission() -> None:
    iam = Mock()
    old = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Action": ["s3:GetObject", "s3:DeleteObject"], "Resource": "*"}
        ],
    }
    new = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Action": "s3:GetObject", "Resource": "*"}],
    }
    iam.get_policy.return_value = {"Policy": {"DefaultVersionId": "v1"}}
    iam.get_policy_version.side_effect = [
        {"PolicyVersion": {"Document": old}},
        {"PolicyVersion": {"Document": old}},
        {"PolicyVersion": {"Document": old}},
        {"PolicyVersion": {"Document": new}},
    ]
    iam.create_policy_version.return_value = {"PolicyVersion": {"VersionId": "v2"}}
    item = finding()
    executor = RemovePolicyPermissionExecutor(iam)
    approvals = ApprovalService()
    engine = RemediationEngine(approvals, [executor])
    params = {
        "policy_arn": "arn:aws:iam::123456789012:policy/test",
        "statement_index": 0,
        "permission_field": "Action",
        "permission_value": "s3:DeleteObject",
    }
    request = engine.review_and_request(
        item, REMOVE_POLICY_PERMISSION, params, "requester"
    ).approval
    approvals.approve(request.approval_id, "reviewer")
    result = engine.remediate(
        item, REMOVE_POLICY_PERMISSION, "operator", params, approval_id=request.approval_id
    )
    assert result.outcome is RemediationOutcome.SUCCEEDED
    written = json_load(iam.create_policy_version.call_args.kwargs["PolicyDocument"])
    assert written["Statement"][0]["Action"] == "s3:GetObject"


def json_load(value: str) -> dict:
    import json

    return json.loads(value)


def test_remove_azure_assignment_and_verify_absence() -> None:
    client = Mock()
    client.role_assignments.get_by_id.side_effect = [
        {"scope": "/subscriptions/x", "principal_id": "p", "role_definition_id": "r"},
        {"scope": "/subscriptions/x", "principal_id": "p", "role_definition_id": "r"},
        ResourceNotFoundError("gone"),
    ]
    item = finding(CloudProvider.AZURE)
    executor = RemoveRBACAssignmentExecutor(client)
    approvals = ApprovalService()
    engine = RemediationEngine(approvals, [executor])
    params = {"role_assignment_id": item.resource.resource_id}
    request = engine.review_and_request(item, REMOVE_RBAC_ASSIGNMENT, params, "requester").approval
    approvals.approve(request.approval_id, "reviewer")
    result = engine.remediate(
        item, REMOVE_RBAC_ASSIGNMENT, "operator", params, approval_id=request.approval_id
    )
    assert result.outcome is RemediationOutcome.SUCCEEDED
    client.role_assignments.delete_by_id.assert_called_once_with(item.resource.resource_id)
