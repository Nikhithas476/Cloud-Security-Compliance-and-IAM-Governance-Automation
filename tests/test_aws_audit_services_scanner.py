"""Mocked tests for AWS CloudTrail and AWS Config security checks."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any
from unittest.mock import MagicMock

import pytest
from botocore.exceptions import ClientError

from cloud_security_governance.aws import AWSCloudTrailConfigScanner
from cloud_security_governance.aws.audit_services_scanner import (
    CLOUDTRAIL_EXISTS_RULE_ID,
    CLOUDTRAIL_LOGGING_RULE_ID,
    CONFIG_COMPLIANCE_RULE_ID,
    CONFIG_RECORDER_RULE_ID,
)
from cloud_security_governance.exceptions import AWSConfigurationError, AWSScanError
from cloud_security_governance.models import ScanResult, Severity

NOW = datetime(2026, 9, 4, 12, 0, tzinfo=UTC)
ACCOUNT_ID = "123456789012"
TRAIL_ARN = f"arn:aws:cloudtrail:us-east-1:{ACCOUNT_ID}:trail/security-trail"
IDENTITY = {
    "Account": ACCOUNT_ID,
    "Arn": f"arn:aws:iam::{ACCOUNT_ID}:user/security-auditor",
    "UserId": "AIDAEXAMPLESECURITY",
}


class FakePaginator:
    def __init__(self, pages: list[dict[str, Any]]) -> None:
        self.pages = pages
        self.calls: list[dict[str, Any]] = []

    def paginate(self, **kwargs: Any) -> list[dict[str, Any]]:
        self.calls.append(kwargs)
        return self.pages


@pytest.fixture(autouse=True)
def clear_aws_environment(monkeypatch) -> None:
    for variable in ("AWS_PROFILE", "AWS_REGION", "AWS_DEFAULT_REGION", "AWS_ROLE_ARN"):
        monkeypatch.delenv(variable, raising=False)


def build_scanner(
    *,
    config_rule_names: list[str] | None = None,
    compliance_pages: list[dict[str, Any]] | None = None,
) -> tuple[
    AWSCloudTrailConfigScanner,
    MagicMock,
    MagicMock,
    MagicMock,
    FakePaginator,
]:
    sts = MagicMock()
    sts.get_caller_identity.return_value = IDENTITY
    cloudtrail = MagicMock()
    cloudtrail.describe_trails.return_value = {
        "trailList": [
            {
                "Name": "security-trail",
                "TrailARN": TRAIL_ARN,
                "HomeRegion": "us-east-1",
                "IsMultiRegionTrail": True,
            }
        ]
    }
    cloudtrail.get_trail_status.return_value = {"IsLogging": True}
    config = MagicMock()
    config.describe_configuration_recorders.return_value = {
        "ConfigurationRecorders": [{"name": "default"}]
    }
    config.describe_configuration_recorder_status.return_value = {
        "ConfigurationRecordersStatus": [{"name": "default", "recording": True}]
    }
    compliance_paginator = FakePaginator(compliance_pages or [{"ComplianceByConfigRules": []}])
    config.get_paginator.return_value = compliance_paginator
    session = MagicMock()
    session.region_name = "us-east-1"
    clients = {"sts": sts, "cloudtrail": cloudtrail, "config": config}
    session.client.side_effect = lambda service, **_kwargs: clients[service]
    clock = MagicMock(side_effect=[NOW, NOW + timedelta(seconds=2)])
    scanner = AWSCloudTrailConfigScanner(
        config_rule_names=config_rule_names,
        session_factory=MagicMock(return_value=session),
        clock=clock,
    )
    return scanner, session, cloudtrail, config, compliance_paginator


def test_compliant_cloudtrail_and_config_produce_no_findings() -> None:
    scanner, _, cloudtrail, config, _ = build_scanner()

    result = scanner.scan()

    assert result.findings == []
    assert result.resources_scanned == 2
    assert result.account.account_id == ACCOUNT_ID
    cloudtrail.describe_trails.assert_called_once_with(includeShadowTrails=False)
    cloudtrail.get_trail_status.assert_called_once_with(Name=TRAIL_ARN)
    config.describe_configuration_recorder_status.assert_called_once_with(
        ConfigurationRecorderNames=["default"]
    )
    config.get_paginator.assert_not_called()


def test_missing_cloudtrail_creates_critical_finding() -> None:
    scanner, _, cloudtrail, _, _ = build_scanner()
    cloudtrail.describe_trails.return_value = {"trailList": []}

    result = scanner.scan()

    assert len(result.findings) == 1
    finding = result.findings[0]
    assert finding.rule_id == CLOUDTRAIL_EXISTS_RULE_ID
    assert finding.severity is Severity.CRITICAL
    assert finding.remediation_available is True
    assert finding.detected_at == NOW
    assert finding.evidence == {"trail_count": 0}
    assert finding.resource.resource_type == "AWS::CloudTrail::Service"
    cloudtrail.get_trail_status.assert_not_called()


def test_disabled_cloudtrail_logging_creates_finding() -> None:
    scanner, _, cloudtrail, _, _ = build_scanner()
    cloudtrail.get_trail_status.return_value = {"IsLogging": False}

    result = scanner.scan()

    assert len(result.findings) == 1
    finding = result.findings[0]
    assert finding.rule_id == CLOUDTRAIL_LOGGING_RULE_ID
    assert finding.severity is Severity.CRITICAL
    assert finding.resource.resource_id == TRAIL_ARN
    assert finding.evidence == {"is_logging": False}


def test_missing_config_recorder_creates_high_finding() -> None:
    scanner, _, _, config, _ = build_scanner()
    config.describe_configuration_recorders.return_value = {"ConfigurationRecorders": []}

    result = scanner.scan()

    assert len(result.findings) == 1
    finding = result.findings[0]
    assert finding.rule_id == CONFIG_RECORDER_RULE_ID
    assert finding.severity is Severity.HIGH
    assert finding.evidence == {"recorder_count": 0, "recording": False}
    assert finding.resource.resource_type == "AWS::Config::Service"
    config.describe_configuration_recorder_status.assert_not_called()


def test_disabled_config_recorder_creates_finding() -> None:
    scanner, _, _, config, _ = build_scanner()
    config.describe_configuration_recorder_status.return_value = {
        "ConfigurationRecordersStatus": [{"name": "default", "recording": False}]
    }

    result = scanner.scan()

    assert len(result.findings) == 1
    finding = result.findings[0]
    assert finding.rule_id == CONFIG_RECORDER_RULE_ID
    assert finding.title == "AWS Config recorder is disabled"
    assert finding.evidence == {"recording": False}


def test_missing_recorder_status_is_treated_as_disabled() -> None:
    scanner, _, _, config, _ = build_scanner()
    config.describe_configuration_recorder_status.return_value = {
        "ConfigurationRecordersStatus": []
    }

    result = scanner.scan()

    assert [finding.rule_id for finding in result.findings] == [CONFIG_RECORDER_RULE_ID]


def test_only_non_compliant_selected_config_rules_create_findings() -> None:
    selected_rules = ["encrypted-volumes", "restricted-ssh", "required-tags"]
    scanner, _, _, _, paginator = build_scanner(
        config_rule_names=selected_rules,
        compliance_pages=[
            {
                "ComplianceByConfigRules": [
                    {
                        "ConfigRuleName": "encrypted-volumes",
                        "Compliance": {"ComplianceType": "COMPLIANT"},
                    },
                    {
                        "ConfigRuleName": "restricted-ssh",
                        "Compliance": {"ComplianceType": "NON_COMPLIANT"},
                    },
                    {
                        "ConfigRuleName": "required-tags",
                        "Compliance": {"ComplianceType": "INSUFFICIENT_DATA"},
                    },
                ]
            }
        ],
    )

    result = scanner.scan()

    config_findings = [
        finding for finding in result.findings if finding.rule_id == CONFIG_COMPLIANCE_RULE_ID
    ]
    assert len(config_findings) == 1
    finding = config_findings[0]
    assert finding.resource.name == "restricted-ssh"
    assert finding.remediation_available is False
    assert finding.evidence == {"compliance_type": "NON_COMPLIANT"}
    assert result.resources_scanned == 5  # Trail, recorder, and three selected rules.
    assert paginator.calls == [{"ConfigRuleNames": selected_rules}]


def test_selected_config_rules_are_batched_in_groups_of_25() -> None:
    selected_rules = [f"selected-rule-{index}" for index in range(26)]
    scanner, _, _, _, paginator = build_scanner(config_rule_names=selected_rules)

    scanner.scan()

    assert paginator.calls == [
        {"ConfigRuleNames": selected_rules[:25]},
        {"ConfigRuleNames": selected_rules[25:]},
    ]


def test_result_round_trips_through_json() -> None:
    scanner, _, cloudtrail, _, _ = build_scanner()
    cloudtrail.get_trail_status.return_value = {"IsLogging": False}

    result = scanner.scan()
    restored = ScanResult.model_validate_json(result.model_dump_json())

    assert restored == result


@pytest.mark.parametrize(
    "rule_names",
    [["invalid rule name"], ["duplicate", "duplicate"], ["x" * 65]],
)
def test_invalid_selected_config_rule_names_are_rejected(rule_names: list[str]) -> None:
    with pytest.raises(AWSConfigurationError, match="Config rule names"):
        AWSCloudTrailConfigScanner(
            config_rule_names=rule_names,
            session_factory=MagicMock(),
        )


def test_config_rule_names_reject_a_single_string() -> None:
    with pytest.raises(AWSConfigurationError, match="collection of names"):
        AWSCloudTrailConfigScanner(
            config_rule_names="selected-rule",
            session_factory=MagicMock(),
        )


def test_region_is_required() -> None:
    session = MagicMock()
    session.region_name = None
    session.client.return_value = MagicMock()

    with pytest.raises(AWSConfigurationError, match="region is required"):
        AWSCloudTrailConfigScanner(session_factory=MagicMock(return_value=session))


def test_cloudtrail_api_error_is_sanitized() -> None:
    scanner, _, cloudtrail, _, _ = build_scanner()
    cloudtrail.describe_trails.side_effect = ClientError(
        {"Error": {"Code": "AccessDeniedException", "Message": "private details"}},
        "DescribeTrails",
    )

    with pytest.raises(AWSScanError, match="AccessDeniedException") as error:
        scanner.scan()

    assert "private details" not in str(error.value)


def test_config_api_error_is_sanitized() -> None:
    scanner, _, _, config, _ = build_scanner()
    config.describe_configuration_recorders.side_effect = ClientError(
        {"Error": {"Code": "AccessDeniedException", "Message": "private details"}},
        "DescribeConfigurationRecorders",
    )

    with pytest.raises(AWSScanError, match="AccessDeniedException") as error:
        scanner.scan()

    assert "private details" not in str(error.value)


def test_unrequested_config_compliance_result_is_rejected() -> None:
    scanner, _, _, _, _ = build_scanner(
        config_rule_names=["selected-rule"],
        compliance_pages=[
            {
                "ComplianceByConfigRules": [
                    {
                        "ConfigRuleName": "different-rule",
                        "Compliance": {"ComplianceType": "NON_COMPLIANT"},
                    }
                ]
            }
        ],
    )

    with pytest.raises(AWSScanError, match="unrequested compliance result"):
        scanner.scan()


def test_invalid_service_responses_are_rejected() -> None:
    scanner, _, cloudtrail, _, _ = build_scanner()
    cloudtrail.describe_trails.return_value = {"trailList": "invalid"}

    with pytest.raises(AWSScanError, match="invalid trail list"):
        scanner.scan()


def test_only_read_only_service_operations_are_invoked() -> None:
    scanner, _, cloudtrail, config, _ = build_scanner(
        config_rule_names=["selected-rule"]
    )

    scanner.scan()

    method_names = {
        method_call[0] for method_call in cloudtrail.method_calls + config.method_calls
    }
    assert method_names <= {
        "describe_trails",
        "get_trail_status",
        "describe_configuration_recorders",
        "describe_configuration_recorder_status",
        "get_paginator",
    }
    assert not any(
        method.startswith(("create_", "delete_", "put_", "start_", "stop_", "update_"))
        for method in method_names
    )
