"""Secret-minimal notification abstractions and webhook delivery."""

from __future__ import annotations

import json
from abc import ABC, abstractmethod
from collections.abc import Callable, Collection
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import urlparse
from urllib.request import Request, urlopen

from cloud_security_governance.exceptions import ConfigurationError, NotificationError
from cloud_security_governance.models import Finding, Severity


class NotificationService(ABC):
    """Delivery contract for high-risk finding notifications."""

    @abstractmethod
    def notify(self, finding: Finding) -> bool:
        """Deliver an alert, returning false when the finding is below threshold."""


class WebhookNotifier(NotificationService):
    """Send allowlisted finding fields to an HTTPS webhook."""

    def __init__(
        self,
        webhook_url: str,
        *,
        alert_severities: Collection[Severity | str] = (Severity.CRITICAL,),
        timeout_seconds: float = 10.0,
        sender: Callable[..., Any] = urlopen,
    ) -> None:
        parsed = urlparse(webhook_url)
        if parsed.scheme != "https" or not parsed.netloc or parsed.username or parsed.password:
            raise ConfigurationError("Webhook URL must be HTTPS and must not contain credentials")
        if timeout_seconds <= 0:
            raise ConfigurationError("Webhook timeout must be positive")
        severities = frozenset(Severity(value) for value in alert_severities)
        if Severity.CRITICAL not in severities:
            raise ConfigurationError("Critical findings must always trigger webhook alerts")
        self.webhook_url = webhook_url
        self.alert_severities = severities
        self.timeout_seconds = timeout_seconds
        self._sender = sender

    def notify(self, finding: Finding) -> bool:
        normalized = Finding.model_validate(finding)
        if normalized.severity not in self.alert_severities:
            return False
        payload = {
            "cloud": normalized.resource.provider.value,
            "account_or_subscription": normalized.resource.account_id,
            "resource": normalized.resource.resource_id,
            "rule": normalized.rule_id,
            "severity": normalized.severity.value,
            "description": normalized.description,
            "finding_id": str(normalized.finding_id),
        }
        request = Request(
            self.webhook_url,
            data=json.dumps(payload, separators=(",", ":")).encode("utf-8"),
            headers={"Content-Type": "application/json", "User-Agent": "cloud-security-governance"},
            method="POST",
        )
        response: Any | None = None
        try:
            response = self._sender(request, timeout=self.timeout_seconds)
            status = getattr(response, "status", None)
            if not isinstance(status, int) or not 200 <= status < 300:
                raise NotificationError("Webhook notification returned an unsuccessful status")
        except NotificationError:
            raise
        except (HTTPError, URLError, OSError) as exc:
            raise NotificationError("Webhook notification could not be delivered") from exc
        finally:
            close = getattr(response, "close", None)
            if callable(close):
                close()
        return True
