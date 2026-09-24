"""Mocked tests for secret-minimal webhook notifications."""

from __future__ import annotations

import json
from unittest.mock import MagicMock
from urllib.error import URLError

import pytest

from cloud_security_governance.exceptions import ConfigurationError, NotificationError
from cloud_security_governance.models import CloudProvider, Finding, Resource, Severity
from cloud_security_governance.notifications import NotificationService, WebhookNotifier


def finding(severity: Severity = Severity.CRITICAL) -> Finding:
    return Finding(
        rule_id="aws.iam.root.access-key",
        resource=Resource(
            resource_id="arn:aws:iam::123456789012:root",
            provider=CloudProvider.AWS,
            account_id="123456789012",
            resource_type="AWS::IAM::RootAccount",
            name="root",
            metadata={"credential": "must-never-be-sent"},
        ),
        title="Root access key exists",
        description="The AWS root account has an active access key.",
        severity=severity,
        evidence={"api_key": "must-never-be-sent"},
    )


def notifier(*, severities=(Severity.CRITICAL,)) -> tuple[WebhookNotifier, MagicMock, MagicMock]:
    response = MagicMock(status=204)
    sender = MagicMock(return_value=response)
    service = WebhookNotifier(
        "https://alerts.example.test/security",
        alert_severities=severities,
        sender=sender,
    )
    return service, sender, response


def test_webhook_notifier_implements_notification_abstraction() -> None:
    service, _, _ = notifier()

    assert isinstance(service, NotificationService)


def test_critical_finding_sends_allowlisted_payload_only() -> None:
    service, sender, response = notifier()
    critical = finding()

    assert service.notify(critical) is True

    request = sender.call_args.args[0]
    payload = json.loads(request.data.decode("utf-8"))
    assert payload == {
        "cloud": "aws",
        "account_or_subscription": "123456789012",
        "resource": "arn:aws:iam::123456789012:root",
        "rule": "aws.iam.root.access-key",
        "severity": "critical",
        "description": "The AWS root account has an active access key.",
        "finding_id": str(critical.finding_id),
    }
    assert "must-never-be-sent" not in request.data.decode("utf-8")
    assert request.get_header("Content-type") == "application/json"
    sender.assert_called_once_with(request, timeout=10.0)
    response.close.assert_called_once_with()


def test_below_threshold_finding_is_not_sent() -> None:
    service, sender, _ = notifier()

    assert service.notify(finding(Severity.HIGH)) is False
    sender.assert_not_called()


def test_high_severity_alerting_can_be_enabled() -> None:
    service, sender, _ = notifier(severities=(Severity.CRITICAL, Severity.HIGH))

    assert service.notify(finding(Severity.HIGH)) is True
    sender.assert_called_once()


@pytest.mark.parametrize(
    "url",
    [
        "http://alerts.example.test/security",
        "https://user:password@alerts.example.test/security",
        "not-a-url",
    ],
)
def test_insecure_or_credential_bearing_webhook_urls_are_rejected(url: str) -> None:
    with pytest.raises(ConfigurationError, match="must be HTTPS"):
        WebhookNotifier(url)


def test_critical_alerts_cannot_be_disabled() -> None:
    with pytest.raises(ConfigurationError, match="Critical"):
        WebhookNotifier(
            "https://alerts.example.test/security",
            alert_severities=(Severity.HIGH,),
        )


def test_webhook_transport_error_is_sanitized() -> None:
    sender = MagicMock(side_effect=URLError("secret endpoint details"))
    service = WebhookNotifier("https://alerts.example.test/security", sender=sender)

    with pytest.raises(NotificationError, match="could not be delivered") as raised:
        service.notify(finding())

    assert "secret endpoint details" not in str(raised.value)


def test_unsuccessful_status_raises_notification_error_and_closes_response() -> None:
    response = MagicMock(status=500)
    sender = MagicMock(return_value=response)
    service = WebhookNotifier("https://alerts.example.test/security", sender=sender)

    with pytest.raises(NotificationError, match="unsuccessful status"):
        service.notify(finding())

    response.close.assert_called_once_with()
