"""Secure, read-only AWS authentication and scanner foundation."""

from __future__ import annotations

import os
import re
from collections.abc import Callable, Mapping
from typing import Any, NoReturn, TypedDict

import boto3
from boto3.session import Session
from botocore.exceptions import (
    BotoCoreError,
    ClientError,
    NoCredentialsError,
    NoRegionError,
    PartialCredentialsError,
    ProfileNotFound,
)

from cloud_security_governance.exceptions import (
    AWSAuthenticationError,
    AWSConfigurationError,
)

_AWS_ACCOUNT_ID_PATTERN = re.compile(r"^\d{12}$")
_AWS_REGION_PATTERN = re.compile(r"^[a-z]{2,}(?:-[a-z0-9]+)+-\d+$")
_AWS_ROLE_ARN_PATTERN = re.compile(
    r"^arn:aws(?:-[a-z0-9-]+)?:iam::\d{12}:role/[A-Za-z0-9+=,.@_/-]{1,512}$"
)
_ROLE_SESSION_NAME = "cloud-security-governance"


class AWSCallerIdentity(TypedDict):
    """Validated subset of the AWS STS GetCallerIdentity response."""

    Account: str
    Arn: str
    UserId: str


class AWSScanner:
    """Build a secure boto3 session and expose read-only identity operations.

    Credential values are never accepted directly. boto3 resolves credentials through its
    standard provider chain, optionally scoped to ``AWS_PROFILE``. When ``AWS_ROLE_ARN`` is set,
    the source session assumes that role and keeps the temporary credentials in memory only.
    """

    def __init__(
        self,
        *,
        profile: str | None = None,
        region: str | None = None,
        role_arn: str | None = None,
        session_factory: Callable[..., Session] = boto3.Session,
    ) -> None:
        self.profile = self._resolve_optional_value(profile, "AWS_PROFILE")
        self.region = self._resolve_region(region)
        self.role_arn = self._resolve_optional_value(role_arn, "AWS_ROLE_ARN")
        self._validate_configuration()
        self._session_factory = session_factory
        self._session = self._create_session()
        self._sts = self._create_sts_client(self._session)

    @staticmethod
    def _resolve_optional_value(explicit_value: str | None, variable: str) -> str | None:
        value = explicit_value if explicit_value is not None else os.getenv(variable)
        if value is None:
            return None
        stripped = value.strip()
        if not stripped:
            raise AWSConfigurationError(f"{variable} must not be empty")
        return stripped

    @classmethod
    def _resolve_region(cls, explicit_region: str | None) -> str | None:
        if explicit_region is not None:
            stripped = explicit_region.strip()
            if not stripped:
                raise AWSConfigurationError("AWS_REGION must not be empty")
            return stripped
        region = os.getenv("AWS_REGION") or os.getenv("AWS_DEFAULT_REGION")
        return region.strip() if region else None

    def _validate_configuration(self) -> None:
        if self.region is not None and not _AWS_REGION_PATTERN.fullmatch(self.region):
            raise AWSConfigurationError("AWS_REGION is not a valid AWS region name")
        if self.role_arn is not None and not _AWS_ROLE_ARN_PATTERN.fullmatch(self.role_arn):
            raise AWSConfigurationError("AWS_ROLE_ARN is not a valid IAM role ARN")

    def _create_session(self) -> Session:
        session_options: dict[str, str] = {}
        if self.profile is not None:
            session_options["profile_name"] = self.profile
        if self.region is not None:
            session_options["region_name"] = self.region

        try:
            source_session = self._session_factory(**session_options)
        except ProfileNotFound as exc:
            raise AWSConfigurationError("The configured AWS profile could not be loaded") from exc
        except (BotoCoreError, OSError) as exc:
            raise AWSConfigurationError("The AWS session could not be initialized") from exc

        if self.role_arn is None:
            return source_session
        return self._assume_role(source_session)

    def _create_sts_client(self, session: Session) -> Any:
        try:
            return session.client("sts", region_name=self.region)
        except NoRegionError as exc:
            raise AWSConfigurationError("No AWS region is configured") from exc
        except (BotoCoreError, OSError) as exc:
            raise AWSConfigurationError("The AWS STS client could not be initialized") from exc

    def _assume_role(self, source_session: Session) -> Session:
        source_sts = self._create_sts_client(source_session)
        try:
            response = source_sts.assume_role(
                RoleArn=self.role_arn,
                RoleSessionName=_ROLE_SESSION_NAME,
            )
        except (NoCredentialsError, PartialCredentialsError) as exc:
            raise AWSAuthenticationError(
                "AWS credentials were not found or are incomplete"
            ) from exc
        except ClientError as exc:
            self._raise_client_authentication_error(exc, "AWS role assumption failed")
        except (BotoCoreError, OSError) as exc:
            raise AWSAuthenticationError("AWS role assumption failed") from exc

        credentials = response.get("Credentials")
        if not isinstance(credentials, Mapping):
            raise AWSAuthenticationError("AWS role assumption returned no credentials")
        required_keys = ("AccessKeyId", "SecretAccessKey", "SessionToken")
        if any(not isinstance(credentials.get(key), str) or not credentials[key] for key in required_keys):
            raise AWSAuthenticationError("AWS role assumption returned incomplete credentials")

        try:
            return self._session_factory(
                aws_access_key_id=credentials["AccessKeyId"],
                aws_secret_access_key=credentials["SecretAccessKey"],
                aws_session_token=credentials["SessionToken"],
                region_name=self.region,
            )
        except (BotoCoreError, OSError) as exc:
            raise AWSAuthenticationError("The assumed-role AWS session could not be created") from exc

    @staticmethod
    def _raise_client_authentication_error(error: ClientError, message: str) -> NoReturn:
        error_details = error.response.get("Error", {})
        error_code = error_details.get("Code") if isinstance(error_details, Mapping) else None
        safe_code = str(error_code) if error_code else "UnknownError"
        raise AWSAuthenticationError(f"{message} ({safe_code})") from error

    def get_caller_identity(self) -> AWSCallerIdentity:
        """Return the authenticated STS identity using a non-destructive API call."""

        try:
            response = self._sts.get_caller_identity()
        except (NoCredentialsError, PartialCredentialsError) as exc:
            raise AWSAuthenticationError(
                "AWS credentials were not found or are incomplete"
            ) from exc
        except ClientError as exc:
            self._raise_client_authentication_error(exc, "AWS authentication failed")
        except (BotoCoreError, OSError) as exc:
            raise AWSAuthenticationError("AWS authentication failed") from exc

        account = response.get("Account")
        arn = response.get("Arn")
        user_id = response.get("UserId")
        if not isinstance(account, str) or not _AWS_ACCOUNT_ID_PATTERN.fullmatch(account):
            raise AWSAuthenticationError("AWS returned an invalid caller account ID")
        if not isinstance(arn, str) or not arn.startswith("arn:"):
            raise AWSAuthenticationError("AWS returned an invalid caller ARN")
        if not isinstance(user_id, str) or not user_id.strip():
            raise AWSAuthenticationError("AWS returned an invalid caller user ID")
        return AWSCallerIdentity(Account=account, Arn=arn, UserId=user_id)

    def validate_authentication(self) -> bool:
        """Validate that boto3 can authenticate to AWS through STS."""

        self.get_caller_identity()
        return True

    def get_account_id(self) -> str:
        """Return the twelve-digit account ID for the active AWS identity."""

        return self.get_caller_identity()["Account"]

    def scan(self) -> NoReturn:
        """Reserve the scanning entry point without performing cloud operations."""

        raise NotImplementedError("AWS resource scanning is not implemented yet")
