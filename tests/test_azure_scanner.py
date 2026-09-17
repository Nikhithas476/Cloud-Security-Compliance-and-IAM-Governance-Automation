"""Mocked tests for secure Azure authentication and scanner behavior."""

from __future__ import annotations

from unittest.mock import MagicMock

import pytest
from azure.core.credentials import AccessToken
from azure.core.exceptions import ClientAuthenticationError
from azure.identity import CredentialUnavailableError

from cloud_security_governance.azure import AzureScanner
from cloud_security_governance.azure.scanner import AZURE_MANAGEMENT_SCOPE
from cloud_security_governance.exceptions import (
    AzureAuthenticationError,
    AzureConfigurationError,
)

SUBSCRIPTION_ID = "11111111-1111-4111-8111-111111111111"
OTHER_SUBSCRIPTION_ID = "22222222-2222-4222-8222-222222222222"
NOW = 1_788_800_000.0


@pytest.fixture(autouse=True)
def clear_azure_subscription(monkeypatch) -> None:
    monkeypatch.delenv("AZURE_SUBSCRIPTION_ID", raising=False)
    monkeypatch.delenv("AZURE_TENANT_ID", raising=False)


def test_credential_is_initialized_once() -> None:
    credential = MagicMock()
    credential_factory = MagicMock(return_value=credential)

    scanner = AzureScanner(
        subscription_id=SUBSCRIPTION_ID,
        credential_factory=credential_factory,
    )

    assert scanner.subscription_id == SUBSCRIPTION_ID
    credential_factory.assert_called_once_with()
    credential.get_token.assert_not_called()


def test_subscription_id_is_loaded_from_environment(monkeypatch) -> None:
    monkeypatch.setenv("AZURE_SUBSCRIPTION_ID", SUBSCRIPTION_ID.upper())

    scanner = AzureScanner(credential_factory=MagicMock())

    assert scanner.subscription_id == SUBSCRIPTION_ID


def test_explicit_subscription_id_overrides_environment(monkeypatch) -> None:
    monkeypatch.setenv("AZURE_SUBSCRIPTION_ID", OTHER_SUBSCRIPTION_ID)

    scanner = AzureScanner(
        subscription_id=SUBSCRIPTION_ID,
        credential_factory=MagicMock(),
    )

    assert scanner.subscription_id == SUBSCRIPTION_ID


@pytest.mark.parametrize(
    ("subscription_id", "message"),
    [
        (None, "is required"),
        (" ", "is required"),
        ("not-a-uuid", "valid UUID"),
        ("00000000-0000-0000-0000-000000000000", "placeholder UUID"),
    ],
)
def test_invalid_subscription_configuration_is_rejected(
    subscription_id: str | None,
    message: str,
) -> None:
    with pytest.raises(AzureConfigurationError, match=message):
        AzureScanner(
            subscription_id=subscription_id,
            credential_factory=MagicMock(),
        )


def test_credential_initialization_error_is_sanitized() -> None:
    credential_factory = MagicMock(
        side_effect=ClientAuthenticationError(message="sensitive upstream details")
    )

    with pytest.raises(AzureConfigurationError, match="could not be initialized") as error:
        AzureScanner(
            subscription_id=SUBSCRIPTION_ID,
            credential_factory=credential_factory,
        )

    assert "sensitive upstream details" not in str(error.value)


def test_authentication_validation_uses_management_scope() -> None:
    credential = MagicMock()
    credential.get_token.return_value = AccessToken("mock-access-token", int(NOW + 3600))
    scanner = AzureScanner(
        subscription_id=SUBSCRIPTION_ID,
        credential_factory=MagicMock(return_value=credential),
        clock=MagicMock(return_value=NOW),
    )

    assert scanner.validate_authentication() is True
    credential.get_token.assert_called_once_with(AZURE_MANAGEMENT_SCOPE)


def test_unavailable_credential_chain_raises_sanitized_error() -> None:
    credential = MagicMock()
    credential.get_token.side_effect = CredentialUnavailableError(
        message="developer credential details"
    )
    scanner = AzureScanner(
        subscription_id=SUBSCRIPTION_ID,
        credential_factory=MagicMock(return_value=credential),
    )

    with pytest.raises(AzureAuthenticationError, match="credential.*chain.*available") as error:
        scanner.validate_authentication()

    assert "developer credential details" not in str(error.value)


def test_client_authentication_failure_is_sanitized() -> None:
    credential = MagicMock()
    credential.get_token.side_effect = ClientAuthenticationError(
        message="tenant-specific authentication details"
    )
    scanner = AzureScanner(
        subscription_id=SUBSCRIPTION_ID,
        credential_factory=MagicMock(return_value=credential),
    )

    with pytest.raises(AzureAuthenticationError, match="authentication failed") as error:
        scanner.validate_authentication()

    assert "tenant-specific authentication details" not in str(error.value)


@pytest.mark.parametrize(
    ("token", "message"),
    [
        (AccessToken("", int(NOW + 3600)), "invalid access token"),
        (AccessToken("mock-access-token", int(NOW - 1)), "expired access token"),
        (MagicMock(token="mock-access-token", expires_on="not-a-timestamp"), "expiration"),
    ],
)
def test_invalid_access_tokens_are_rejected(token: object, message: str) -> None:
    credential = MagicMock()
    credential.get_token.return_value = token
    scanner = AzureScanner(
        subscription_id=SUBSCRIPTION_ID,
        credential_factory=MagicMock(return_value=credential),
        clock=MagicMock(return_value=NOW),
    )

    with pytest.raises(AzureAuthenticationError, match=message):
        scanner.validate_authentication()


def test_aggregate_scan_requires_tenant_id() -> None:
    credential = MagicMock()
    scanner = AzureScanner(
        subscription_id=SUBSCRIPTION_ID,
        credential_factory=MagicMock(return_value=credential),
    )

    with pytest.raises(AzureConfigurationError, match="AZURE_TENANT_ID is required"):
        scanner.scan()

    credential.get_token.assert_not_called()
