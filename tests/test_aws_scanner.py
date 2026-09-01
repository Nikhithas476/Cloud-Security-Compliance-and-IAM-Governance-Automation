"""Mocked tests for secure AWS authentication and scanner behavior."""

from datetime import UTC, datetime
from unittest.mock import MagicMock, call

import pytest
from botocore.exceptions import ClientError, NoCredentialsError, ProfileNotFound

from cloud_security_governance.aws import AWSScanner
from cloud_security_governance.exceptions import (
    AWSAuthenticationError,
    AWSConfigurationError,
)

IDENTITY = {
    "Account": "123456789012",
    "Arn": "arn:aws:iam::123456789012:user/security-auditor",
    "UserId": "AIDAEXAMPLESECURITY",
    "ResponseMetadata": {"RequestId": "example-request-id"},
}
ROLE_ARN = "arn:aws:iam::123456789012:role/SecurityAuditRole"


def scanner_with_identity(identity: dict[str, object] | None = None) -> tuple[AWSScanner, MagicMock]:
    sts = MagicMock()
    sts.get_caller_identity.return_value = identity or IDENTITY
    session = MagicMock()
    session.client.return_value = sts
    return AWSScanner(session_factory=MagicMock(return_value=session)), sts


def test_standard_boto3_resolution_uses_no_explicit_credentials(monkeypatch) -> None:
    for variable in ("AWS_PROFILE", "AWS_REGION", "AWS_DEFAULT_REGION", "AWS_ROLE_ARN"):
        monkeypatch.delenv(variable, raising=False)
    session = MagicMock()
    session.client.return_value = MagicMock()
    session_factory = MagicMock(return_value=session)

    AWSScanner(session_factory=session_factory)

    session_factory.assert_called_once_with()
    session.client.assert_called_once_with("sts", region_name=None)


def test_profile_region_and_role_are_loaded_from_environment(monkeypatch) -> None:
    monkeypatch.setenv("AWS_PROFILE", "security-audit")
    monkeypatch.setenv("AWS_REGION", "us-west-2")
    monkeypatch.setenv("AWS_ROLE_ARN", ROLE_ARN)
    source_sts = MagicMock()
    source_sts.assume_role.return_value = {
        "Credentials": {
            "AccessKeyId": "temporary-access-key",
            "SecretAccessKey": "temporary-secret-key",
            "SessionToken": "temporary-session-token",
            "Expiration": datetime(2026, 1, 1, tzinfo=UTC),
        }
    }
    source_session = MagicMock()
    source_session.client.return_value = source_sts
    assumed_session = MagicMock()
    assumed_session.client.return_value = MagicMock()
    session_factory = MagicMock(side_effect=[source_session, assumed_session])

    scanner = AWSScanner(session_factory=session_factory)

    assert scanner.profile == "security-audit"
    assert scanner.region == "us-west-2"
    assert scanner.role_arn == ROLE_ARN
    assert session_factory.call_args_list == [
        call(profile_name="security-audit", region_name="us-west-2"),
        call(
            aws_access_key_id="temporary-access-key",
            aws_secret_access_key="temporary-secret-key",
            aws_session_token="temporary-session-token",
            region_name="us-west-2",
        ),
    ]
    source_sts.assume_role.assert_called_once_with(
        RoleArn=ROLE_ARN,
        RoleSessionName="cloud-security-governance",
    )
    source_sts.get_caller_identity.assert_not_called()


def test_explicit_options_override_environment(monkeypatch) -> None:
    monkeypatch.setenv("AWS_PROFILE", "environment-profile")
    monkeypatch.setenv("AWS_REGION", "us-east-1")
    session = MagicMock()
    session.client.return_value = MagicMock()
    session_factory = MagicMock(return_value=session)

    scanner = AWSScanner(
        profile="explicit-profile",
        region="eu-west-1",
        session_factory=session_factory,
    )

    assert scanner.profile == "explicit-profile"
    assert scanner.region == "eu-west-1"
    session_factory.assert_called_once_with(
        profile_name="explicit-profile",
        region_name="eu-west-1",
    )


def test_get_caller_identity_returns_only_validated_fields() -> None:
    scanner, sts = scanner_with_identity()

    identity = scanner.get_caller_identity()

    assert identity == {
        "Account": "123456789012",
        "Arn": "arn:aws:iam::123456789012:user/security-auditor",
        "UserId": "AIDAEXAMPLESECURITY",
    }
    sts.get_caller_identity.assert_called_once_with()


def test_get_account_id_and_authentication_validation() -> None:
    scanner, sts = scanner_with_identity()

    assert scanner.get_account_id() == "123456789012"
    assert scanner.validate_authentication() is True
    assert sts.get_caller_identity.call_count == 2


@pytest.mark.parametrize(
    "identity",
    [
        {**IDENTITY, "Account": "invalid"},
        {**IDENTITY, "Arn": "not-an-arn"},
        {**IDENTITY, "UserId": ""},
    ],
)
def test_invalid_sts_identity_is_rejected(identity: dict[str, object]) -> None:
    scanner, _ = scanner_with_identity(identity)

    with pytest.raises(AWSAuthenticationError, match="invalid caller"):
        scanner.get_caller_identity()


def test_missing_credentials_raise_sanitized_error() -> None:
    scanner, sts = scanner_with_identity()
    sts.get_caller_identity.side_effect = NoCredentialsError()

    with pytest.raises(AWSAuthenticationError, match="not found or are incomplete") as error:
        scanner.get_caller_identity()

    assert "secret" not in str(error.value).lower()


def test_client_error_exposes_only_aws_error_code() -> None:
    scanner, sts = scanner_with_identity()
    sts.get_caller_identity.side_effect = ClientError(
        {
            "Error": {
                "Code": "AccessDenied",
                "Message": "sensitive upstream details",
            }
        },
        "GetCallerIdentity",
    )

    with pytest.raises(AWSAuthenticationError, match=r"AccessDenied") as error:
        scanner.get_caller_identity()

    assert "sensitive upstream details" not in str(error.value)


def test_missing_profile_is_configuration_error() -> None:
    session_factory = MagicMock(side_effect=ProfileNotFound(profile="missing"))

    with pytest.raises(AWSConfigurationError, match="profile could not be loaded"):
        AWSScanner(profile="missing", session_factory=session_factory)


@pytest.mark.parametrize(
    ("kwargs", "message"),
    [
        ({"region": "not_a_region"}, "valid AWS region"),
        ({"role_arn": "not-an-arn"}, "valid IAM role ARN"),
        ({"profile": " "}, "AWS_PROFILE must not be empty"),
    ],
)
def test_invalid_configuration_is_rejected(
    kwargs: dict[str, str], message: str
) -> None:
    with pytest.raises(AWSConfigurationError, match=message):
        AWSScanner(session_factory=MagicMock(), **kwargs)


def test_incomplete_assume_role_response_is_rejected() -> None:
    source_sts = MagicMock()
    source_sts.assume_role.return_value = {"Credentials": {"AccessKeyId": "temporary"}}
    source_session = MagicMock()
    source_session.client.return_value = source_sts

    with pytest.raises(AWSAuthenticationError, match="incomplete credentials"):
        AWSScanner(
            role_arn=ROLE_ARN,
            session_factory=MagicMock(return_value=source_session),
        )


def test_scan_is_an_explicit_non_operational_placeholder() -> None:
    scanner, sts = scanner_with_identity()

    with pytest.raises(NotImplementedError, match="not implemented yet"):
        scanner.scan()

    sts.get_caller_identity.assert_not_called()
    sts.assume_role.assert_not_called()

