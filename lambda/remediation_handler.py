"""AWS Lambda adapter for the approval-gated remediation engine."""

from __future__ import annotations

import json
import logging
from collections.abc import Callable
from typing import Any
from uuid import UUID

from cloud_security_governance.bootstrap import get_remediation_engine
from cloud_security_governance.models import Finding
from cloud_security_governance.remediation import RemediationEngine

logger = logging.getLogger(__name__)
_engine_factory: Callable[[], RemediationEngine] = get_remediation_engine


def configure_engine(factory: Callable[[], RemediationEngine]) -> None:
    global _engine_factory
    _engine_factory = factory


def lambda_handler(event: dict[str, Any], context: Any) -> dict[str, Any]:
    del context
    try:
        body = event.get("body", event)
        body = json.loads(body) if isinstance(body, str) else body
        if not isinstance(body, dict):
            raise TypeError("Request body must be a JSON object")
        dry_run = bool(body.get("dry_run", False))
        approval_id = body.get("approval_id")
        if not dry_run and not approval_id:
            return _response(403, {"error": "Explicit approval is required"})
        result = _engine_factory().remediate(
            Finding.model_validate(body["finding"]),
            str(body["action"]),
            str(body["actor"]),
            body.get("parameters", {}),
            approval_id=UUID(approval_id) if approval_id else None,
            dry_run=dry_run,
        )
        status = 200 if result.executed or result.dry_run else 403
        logger.info("remediation_lambda_completed finding_id=%s", result.finding_id)
        return _response(status, result.model_dump(mode="json"))
    except (KeyError, TypeError, ValueError, json.JSONDecodeError) as exc:
        logger.warning("remediation_lambda_invalid_request type=%s", type(exc).__name__)
        return _response(400, {"error": "Invalid remediation request"})
    except Exception as exc:
        logger.exception("remediation_lambda_failed")
        return _response(500, {"error": "Remediation request failed", "type": type(exc).__name__})


def _response(status: int, body: dict[str, Any]) -> dict[str, Any]:
    return {"statusCode": status, "body": json.dumps(body)}
