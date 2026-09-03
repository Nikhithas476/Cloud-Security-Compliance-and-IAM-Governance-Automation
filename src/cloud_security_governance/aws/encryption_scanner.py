"""Read-only AWS encryption compliance scanner for S3 and EBS."""

from __future__ import annotations

from collections.abc import Callable, Collection, Mapping
from datetime import UTC, datetime
from typing import Any, NoReturn

import boto3
from boto3.session import Session
from botocore.exceptions import BotoCoreError, ClientError, NoRegionError

from cloud_security_governance.aws.scanner import AWSScanner
from cloud_security_governance.exceptions import AWSConfigurationError, AWSScanError
from cloud_security_governance.models import (
    CloudAccount,
    CloudProvider,
    Finding,
    Resource,
    ScanResult,
    Severity,
)

S3_BUCKET_ENCRYPTION_RULE_ID = "aws.s3.bucket.encryption-enabled"
EBS_VOLUME_ENCRYPTION_RULE_ID = "aws.ec2.ebs.volume-encryption-enabled"
SUPPORTED_ENCRYPTION_RULES = frozenset(
    {S3_BUCKET_ENCRYPTION_RULE_ID, EBS_VOLUME_ENCRYPTION_RULE_ID}
)
_MISSING_S3_ENCRYPTION_CODES = frozenset(
    {"ServerSideEncryptionConfigurationNotFoundError"}
)


def _utc_now() -> datetime:
    return datetime.now(UTC)


class AWSEncryptionScanner(AWSScanner):
    """Detect unencrypted S3 buckets and EBS volumes without changing resources."""

    def __init__(
        self,
        *,
        profile: str | None = None,
        region: str | None = None,
        role_arn: str | None = None,
        enabled_rules: Collection[str] | None = None,
        session_factory: Callable[..., Session] = boto3.Session,
        clock: Callable[[], datetime] = _utc_now,
    ) -> None:
        self.enabled_rules = self._validate_enabled_rules(enabled_rules)
        self._clock = clock
        super().__init__(
            profile=profile,
            region=region,
            role_arn=role_arn,
            session_factory=session_factory,
        )
        session_region = getattr(self._session, "region_name", None)
        self._effective_region = self.region or (
            session_region if isinstance(session_region, str) and session_region else None
        )
        if EBS_VOLUME_ENCRYPTION_RULE_ID in self.enabled_rules and self._effective_region is None:
            raise AWSConfigurationError("An AWS region is required to scan EBS volumes")

        self._s3 = (
            self._create_client("s3", self._effective_region)
            if S3_BUCKET_ENCRYPTION_RULE_ID in self.enabled_rules
            else None
        )
        self._ec2 = (
            self._create_client("ec2", self._effective_region)
            if EBS_VOLUME_ENCRYPTION_RULE_ID in self.enabled_rules
            else None
        )

    @staticmethod
    def _validate_enabled_rules(enabled_rules: Collection[str] | None) -> frozenset[str]:
        selected = (
            SUPPORTED_ENCRYPTION_RULES
            if enabled_rules is None
            else frozenset(enabled_rules)
        )
        unknown = selected - SUPPORTED_ENCRYPTION_RULES
        if unknown:
            names = ", ".join(sorted(unknown))
            raise AWSConfigurationError(f"Unsupported AWS encryption rule(s): {names}")
        return frozenset(selected)

    def _create_client(self, service: str, region: str | None) -> Any:
        try:
            return self._session.client(service, region_name=region)
        except NoRegionError as exc:
            raise AWSConfigurationError(f"An AWS region is required for {service}") from exc
        except (BotoCoreError, OSError) as exc:
            raise AWSConfigurationError(f"The AWS {service} client could not be initialized") from exc

    def scan(self) -> ScanResult:
        """Run configured read-only encryption checks and return common findings."""

        started_at = self._aware_utc(self._clock(), "scan timestamp")
        identity = self.get_caller_identity()
        account_id = identity["Account"]
        partition = identity["Arn"].split(":", maxsplit=2)[1]
        findings: list[Finding] = []
        resource_ids: set[str] = set()

        try:
            if S3_BUCKET_ENCRYPTION_RULE_ID in self.enabled_rules:
                self._scan_s3(account_id, partition, findings, resource_ids, started_at)
            if EBS_VOLUME_ENCRYPTION_RULE_ID in self.enabled_rules:
                self._scan_ebs(account_id, partition, findings, resource_ids, started_at)
        except ClientError as exc:
            self._raise_scan_client_error(exc)
        except (BotoCoreError, OSError) as exc:
            raise AWSScanError("The AWS encryption scan could not be completed") from exc

        completed_at = max(
            self._aware_utc(self._clock(), "scan timestamp"),
            started_at,
        )
        return ScanResult(
            account=CloudAccount(
                account_id=account_id,
                provider=CloudProvider.AWS,
                display_name=f"AWS account {account_id}",
            ),
            started_at=started_at,
            completed_at=completed_at,
            resources_scanned=len(resource_ids),
            findings=findings,
        )

    def _scan_s3(
        self,
        account_id: str,
        partition: str,
        findings: list[Finding],
        resource_ids: set[str],
        detected_at: datetime,
    ) -> None:
        if self._s3 is None:
            return
        response = self._s3.list_buckets()
        buckets = response.get("Buckets", [])
        if not isinstance(buckets, list):
            raise AWSScanError("AWS S3 returned an invalid bucket list")

        for bucket in buckets:
            if not isinstance(bucket, Mapping):
                raise AWSScanError("AWS S3 returned an invalid bucket item")
            bucket_name = self._required_string(bucket, "Name", "S3 bucket")
            bucket_region = self._get_bucket_region(bucket_name)
            resource = Resource(
                resource_id=f"arn:{partition}:s3:::{bucket_name}",
                provider=CloudProvider.AWS,
                account_id=account_id,
                resource_type="AWS::S3::Bucket",
                name=bucket_name,
                region=bucket_region,
            )
            resource_ids.add(resource.resource_id)
            algorithms = self._get_bucket_encryption_algorithms(bucket_name)
            if algorithms:
                continue
            findings.append(
                Finding(
                    rule_id=S3_BUCKET_ENCRYPTION_RULE_ID,
                    resource=resource,
                    title="S3 bucket default encryption is not configured",
                    description=(
                        f"S3 bucket {bucket_name} has no valid default server-side encryption "
                        "configuration."
                    ),
                    severity=Severity.HIGH,
                    remediation_available=True,
                    evidence={"encryption_algorithms": []},
                    detected_at=detected_at,
                )
            )

    def _get_bucket_region(self, bucket_name: str) -> str:
        if self._s3 is None:
            raise AWSScanError("The AWS S3 client is not configured")
        response = self._s3.get_bucket_location(Bucket=bucket_name)
        location = response.get("LocationConstraint")
        if location is None:
            return "us-east-1"
        if location == "EU":
            return "eu-west-1"
        if not isinstance(location, str) or not location.strip():
            raise AWSScanError("AWS S3 returned an invalid bucket location")
        return location

    def _get_bucket_encryption_algorithms(self, bucket_name: str) -> list[str]:
        if self._s3 is None:
            raise AWSScanError("The AWS S3 client is not configured")
        try:
            response = self._s3.get_bucket_encryption(Bucket=bucket_name)
        except ClientError as exc:
            if self._client_error_code(exc) in _MISSING_S3_ENCRYPTION_CODES:
                return []
            raise

        configuration = response.get("ServerSideEncryptionConfiguration", {})
        if not isinstance(configuration, Mapping):
            raise AWSScanError("AWS S3 returned an invalid encryption configuration")
        rules = configuration.get("Rules", [])
        if not isinstance(rules, list):
            raise AWSScanError("AWS S3 returned an invalid encryption rule list")

        algorithms: list[str] = []
        for rule in rules:
            if not isinstance(rule, Mapping):
                raise AWSScanError("AWS S3 returned an invalid encryption rule")
            defaults = rule.get("ApplyServerSideEncryptionByDefault", {})
            if not isinstance(defaults, Mapping):
                raise AWSScanError("AWS S3 returned invalid encryption defaults")
            algorithm = defaults.get("SSEAlgorithm")
            if isinstance(algorithm, str) and algorithm.strip():
                algorithms.append(algorithm.strip())
        return algorithms

    def _scan_ebs(
        self,
        account_id: str,
        partition: str,
        findings: list[Finding],
        resource_ids: set[str],
        detected_at: datetime,
    ) -> None:
        if self._ec2 is None or self._effective_region is None:
            return
        paginator = self._ec2.get_paginator("describe_volumes")
        for page in paginator.paginate():
            volumes = page.get("Volumes", [])
            if not isinstance(volumes, list):
                raise AWSScanError("AWS EC2 returned an invalid EBS volume list")
            for volume in volumes:
                if not isinstance(volume, Mapping):
                    raise AWSScanError("AWS EC2 returned an invalid EBS volume item")
                volume_id = self._required_string(volume, "VolumeId", "EBS volume")
                encrypted = volume.get("Encrypted")
                if not isinstance(encrypted, bool):
                    raise AWSScanError("AWS EC2 returned an invalid EBS encryption status")
                availability_zone = volume.get("AvailabilityZone")
                metadata = {
                    "availability_zone": (
                        availability_zone if isinstance(availability_zone, str) else None
                    ),
                    "state": str(volume.get("State", "unknown")),
                }
                resource = Resource(
                    resource_id=(
                        f"arn:{partition}:ec2:{self._effective_region}:{account_id}:"
                        f"volume/{volume_id}"
                    ),
                    provider=CloudProvider.AWS,
                    account_id=account_id,
                    resource_type="AWS::EC2::Volume",
                    name=volume_id,
                    region=self._effective_region,
                    metadata=metadata,
                )
                resource_ids.add(resource.resource_id)
                if encrypted:
                    continue
                findings.append(
                    Finding(
                        rule_id=EBS_VOLUME_ENCRYPTION_RULE_ID,
                        resource=resource,
                        title="EBS volume is not encrypted",
                        description=(
                            f"EBS volume {volume_id} is not encrypted at rest in "
                            f"{self._effective_region}."
                        ),
                        severity=Severity.HIGH,
                        remediation_available=True,
                        evidence={"encrypted": False},
                        detected_at=detected_at,
                    )
                )

    @staticmethod
    def _required_string(value: Mapping[str, Any], key: str, context: str) -> str:
        result = value.get(key)
        if not isinstance(result, str) or not result.strip():
            raise AWSScanError(f"AWS returned an invalid {context} {key}")
        return result.strip()

    @staticmethod
    def _aware_utc(value: datetime, context: str) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise AWSScanError(f"AWS returned a timezone-naive {context}")
        return value.astimezone(UTC)

    @staticmethod
    def _client_error_code(error: ClientError) -> str | None:
        details = error.response.get("Error", {})
        code = details.get("Code") if isinstance(details, Mapping) else None
        return str(code) if code else None

    @classmethod
    def _raise_scan_client_error(cls, error: ClientError) -> NoReturn:
        code = cls._client_error_code(error) or "UnknownError"
        raise AWSScanError(f"The AWS encryption scan could not be completed ({code})") from error
