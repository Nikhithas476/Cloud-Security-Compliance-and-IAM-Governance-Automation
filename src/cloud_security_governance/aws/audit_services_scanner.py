"""Read-only AWS CloudTrail and AWS Config security checks."""

from __future__ import annotations

import re
from collections.abc import Callable, Collection, Iterator, Mapping
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

CLOUDTRAIL_EXISTS_RULE_ID = "aws.cloudtrail.trail.exists"
CLOUDTRAIL_LOGGING_RULE_ID = "aws.cloudtrail.logging.enabled"
CONFIG_RECORDER_RULE_ID = "aws.config.recorder.enabled"
CONFIG_COMPLIANCE_RULE_ID = "aws.config.rule.compliant"

_CONFIG_RULE_NAME_PATTERN = re.compile(r"^[A-Za-z0-9_-]{1,64}$")
_CONFIG_RULE_BATCH_SIZE = 25
_VALID_COMPLIANCE_TYPES = frozenset(
    {"COMPLIANT", "NON_COMPLIANT", "NOT_APPLICABLE", "INSUFFICIENT_DATA"}
)


def _utc_now() -> datetime:
    return datetime.now(UTC)


class AWSCloudTrailConfigScanner(AWSScanner):
    """Check CloudTrail and AWS Config using non-mutating API operations."""

    def __init__(
        self,
        *,
        profile: str | None = None,
        region: str | None = None,
        role_arn: str | None = None,
        config_rule_names: Collection[str] | None = None,
        session_factory: Callable[..., Session] = boto3.Session,
        clock: Callable[[], datetime] = _utc_now,
    ) -> None:
        self.config_rule_names = self._validate_config_rule_names(config_rule_names)
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
        if self._effective_region is None:
            raise AWSConfigurationError("An AWS region is required for CloudTrail and Config scans")
        self._cloudtrail = self._create_client("cloudtrail")
        self._config = self._create_client("config")

    @staticmethod
    def _validate_config_rule_names(config_rule_names: Collection[str] | None) -> tuple[str, ...]:
        if config_rule_names is None:
            return ()
        if isinstance(config_rule_names, str):
            raise AWSConfigurationError("AWS Config rule names must be a collection of names")
        normalized: list[str] = []
        for name in config_rule_names:
            if not isinstance(name, str) or not _CONFIG_RULE_NAME_PATTERN.fullmatch(name.strip()):
                raise AWSConfigurationError("AWS Config rule names must be 1-64 safe characters")
            normalized.append(name.strip())
        if len(normalized) != len(set(normalized)):
            raise AWSConfigurationError("AWS Config rule names must not contain duplicates")
        return tuple(normalized)

    def _create_client(self, service: str) -> Any:
        try:
            return self._session.client(service, region_name=self._effective_region)
        except NoRegionError as exc:
            raise AWSConfigurationError(f"An AWS region is required for {service}") from exc
        except (BotoCoreError, OSError) as exc:
            raise AWSConfigurationError(f"The AWS {service} client could not be initialized") from exc

    def scan(self) -> ScanResult:
        """Run CloudTrail and Config checks and return provider-neutral findings."""

        started_at = self._aware_utc(self._clock(), "scan timestamp")
        identity = self.get_caller_identity()
        account_id = identity["Account"]
        partition = identity["Arn"].split(":", maxsplit=2)[1]
        findings: list[Finding] = []
        resource_ids: set[str] = set()

        try:
            self._scan_cloudtrail(account_id, partition, findings, resource_ids, started_at)
            self._scan_config_recorder(account_id, findings, resource_ids, started_at)
            self._scan_config_compliance(account_id, findings, resource_ids, started_at)
        except ClientError as exc:
            self._raise_scan_client_error(exc)
        except (BotoCoreError, OSError) as exc:
            raise AWSScanError("The AWS audit-services scan could not be completed") from exc

        completed_at = max(self._aware_utc(self._clock(), "scan timestamp"), started_at)
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

    def _scan_cloudtrail(
        self,
        account_id: str,
        partition: str,
        findings: list[Finding],
        resource_ids: set[str],
        detected_at: datetime,
    ) -> None:
        response = self._cloudtrail.describe_trails(includeShadowTrails=False)
        trails = response.get("trailList", [])
        if not isinstance(trails, list):
            raise AWSScanError("AWS CloudTrail returned an invalid trail list")
        if not trails:
            resource = self._service_resource(account_id, "cloudtrail", "AWS::CloudTrail::Service")
            resource_ids.add(resource.resource_id)
            findings.append(
                Finding(
                    rule_id=CLOUDTRAIL_EXISTS_RULE_ID,
                    resource=resource,
                    title="No CloudTrail trail exists",
                    description=(
                        f"AWS account {account_id} has no CloudTrail trail in "
                        f"{self._effective_region}."
                    ),
                    severity=Severity.CRITICAL,
                    remediation_available=True,
                    evidence={"trail_count": 0},
                    detected_at=detected_at,
                )
            )
            return

        for trail in trails:
            if not isinstance(trail, Mapping):
                raise AWSScanError("AWS CloudTrail returned an invalid trail item")
            trail_name = self._required_string(trail, "Name", "CloudTrail trail")
            trail_arn = self._required_string(trail, "TrailARN", "CloudTrail trail")
            home_region = trail.get("HomeRegion", self._effective_region)
            if not isinstance(home_region, str) or not home_region.strip():
                raise AWSScanError("AWS CloudTrail returned an invalid trail HomeRegion")
            resource = Resource(
                resource_id=trail_arn,
                provider=CloudProvider.AWS,
                account_id=account_id,
                resource_type="AWS::CloudTrail::Trail",
                name=trail_name,
                region=home_region,
                metadata={"multi_region": bool(trail.get("IsMultiRegionTrail", False))},
            )
            resource_ids.add(resource.resource_id)
            status = self._cloudtrail.get_trail_status(Name=trail_arn)
            is_logging = status.get("IsLogging")
            if not isinstance(is_logging, bool):
                raise AWSScanError("AWS CloudTrail returned an invalid logging status")
            if not is_logging:
                findings.append(
                    Finding(
                        rule_id=CLOUDTRAIL_LOGGING_RULE_ID,
                        resource=resource,
                        title="CloudTrail logging is disabled",
                        description=f"CloudTrail trail {trail_name} is not actively logging.",
                        severity=Severity.CRITICAL,
                        remediation_available=True,
                        evidence={"is_logging": False},
                        detected_at=detected_at,
                    )
                )

    def _scan_config_recorder(
        self,
        account_id: str,
        findings: list[Finding],
        resource_ids: set[str],
        detected_at: datetime,
    ) -> None:
        response = self._config.describe_configuration_recorders()
        recorders = response.get("ConfigurationRecorders", [])
        if not isinstance(recorders, list):
            raise AWSScanError("AWS Config returned an invalid recorder list")
        if not recorders:
            resource = self._service_resource(account_id, "config", "AWS::Config::Service")
            resource_ids.add(resource.resource_id)
            findings.append(
                Finding(
                    rule_id=CONFIG_RECORDER_RULE_ID,
                    resource=resource,
                    title="AWS Config recorder is not configured",
                    description=(
                        f"AWS Config has no configuration recorder in {self._effective_region}."
                    ),
                    severity=Severity.HIGH,
                    remediation_available=True,
                    evidence={"recorder_count": 0, "recording": False},
                    detected_at=detected_at,
                )
            )
            return

        recorder_names = [
            self._required_string(recorder, "name", "AWS Config recorder")
            for recorder in recorders
            if isinstance(recorder, Mapping)
        ]
        if len(recorder_names) != len(recorders):
            raise AWSScanError("AWS Config returned an invalid recorder item")
        status_response = self._config.describe_configuration_recorder_status(
            ConfigurationRecorderNames=recorder_names
        )
        statuses = status_response.get("ConfigurationRecordersStatus", [])
        if not isinstance(statuses, list):
            raise AWSScanError("AWS Config returned an invalid recorder status list")
        status_by_name: dict[str, Mapping[str, Any]] = {}
        for status in statuses:
            if not isinstance(status, Mapping):
                raise AWSScanError("AWS Config returned an invalid recorder status")
            name = self._required_string(status, "name", "AWS Config recorder status")
            status_by_name[name] = status

        for recorder_name in recorder_names:
            resource = Resource(
                resource_id=(
                    f"aws-config-recorder:{self._effective_region}:{account_id}:{recorder_name}"
                ),
                provider=CloudProvider.AWS,
                account_id=account_id,
                resource_type="AWS::Config::ConfigurationRecorder",
                name=recorder_name,
                region=self._effective_region,
            )
            resource_ids.add(resource.resource_id)
            recorder_status = status_by_name.get(recorder_name)
            recording = recorder_status.get("recording") if recorder_status else False
            if not isinstance(recording, bool):
                raise AWSScanError("AWS Config returned an invalid recorder recording status")
            if not recording:
                findings.append(
                    Finding(
                        rule_id=CONFIG_RECORDER_RULE_ID,
                        resource=resource,
                        title="AWS Config recorder is disabled",
                        description=(
                            f"AWS Config recorder {recorder_name} is not recording in "
                            f"{self._effective_region}."
                        ),
                        severity=Severity.HIGH,
                        remediation_available=True,
                        evidence={"recording": False},
                        detected_at=detected_at,
                    )
                )

    def _scan_config_compliance(
        self,
        account_id: str,
        findings: list[Finding],
        resource_ids: set[str],
        detected_at: datetime,
    ) -> None:
        selected = set(self.config_rule_names)
        for batch in self._batched(self.config_rule_names, _CONFIG_RULE_BATCH_SIZE):
            paginator = self._config.get_paginator("describe_compliance_by_config_rule")
            for page in paginator.paginate(ConfigRuleNames=list(batch)):
                results = page.get("ComplianceByConfigRules", [])
                if not isinstance(results, list):
                    raise AWSScanError("AWS Config returned an invalid compliance result list")
                for result in results:
                    if not isinstance(result, Mapping):
                        raise AWSScanError("AWS Config returned an invalid compliance result")
                    rule_name = self._required_string(
                        result, "ConfigRuleName", "AWS Config compliance result"
                    )
                    if rule_name not in selected:
                        raise AWSScanError("AWS Config returned an unrequested compliance result")
                    compliance = result.get("Compliance")
                    if not isinstance(compliance, Mapping):
                        raise AWSScanError("AWS Config returned invalid compliance details")
                    compliance_type = self._required_string(
                        compliance, "ComplianceType", "AWS Config compliance result"
                    )
                    if compliance_type not in _VALID_COMPLIANCE_TYPES:
                        raise AWSScanError("AWS Config returned an unknown compliance type")
                    resource = Resource(
                        resource_id=(
                            f"aws-config-rule:{self._effective_region}:{account_id}:{rule_name}"
                        ),
                        provider=CloudProvider.AWS,
                        account_id=account_id,
                        resource_type="AWS::Config::ConfigRule",
                        name=rule_name,
                        region=self._effective_region,
                    )
                    resource_ids.add(resource.resource_id)
                    if compliance_type != "NON_COMPLIANT":
                        continue
                    findings.append(
                        Finding(
                            rule_id=CONFIG_COMPLIANCE_RULE_ID,
                            resource=resource,
                            title="AWS Config rule is non-compliant",
                            description=(
                                f"Selected AWS Config rule {rule_name} reports NON_COMPLIANT in "
                                f"{self._effective_region}."
                            ),
                            severity=Severity.HIGH,
                            remediation_available=False,
                            evidence={"compliance_type": compliance_type},
                            detected_at=detected_at,
                        )
                    )

    def _service_resource(self, account_id: str, name: str, resource_type: str) -> Resource:
        return Resource(
            resource_id=f"aws-service:{name}:{self._effective_region}:{account_id}",
            provider=CloudProvider.AWS,
            account_id=account_id,
            resource_type=resource_type,
            name=name,
            region=self._effective_region,
        )

    @staticmethod
    def _batched(values: tuple[str, ...], size: int) -> Iterator[tuple[str, ...]]:
        for index in range(0, len(values), size):
            yield values[index : index + size]

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
        raise AWSScanError(f"The AWS audit-services scan could not be completed ({code})") from error
