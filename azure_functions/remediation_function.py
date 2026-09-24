"""Azure Function adapter for approved remediation requests."""

from __future__ import annotations

import logging
from collections.abc import Callable
from typing import Any
from uuid import UUID

from cloud_security_governance.models import Finding
from cloud_security_governance.remediation import RemediationEngine

logger = logging.getLogger(__name__)
_engine_factory: Callable[[], RemediationEngine] | None = None


def configure_engine(factory: Callable[[], RemediationEngine]) -> None:
    global _engine_factory
    _engine_factory = factory


def main(request: Any) -> dict[str, Any]:
    try:
        if _engine_factory is None:
            raise RuntimeError("The remediation engine is not configured")
        body = request.get_json() if hasattr(request, "get_json") else request
        if not isinstance(body, dict):
            raise TypeError("Request body must be a JSON object")
        dry_run = bool(body.get("dry_run", False))
        approval_id = body.get("approval_id")
        if not dry_run and not approval_id:
            return {"status_code": 403, "json": {"error": "Explicit approval is required"}}
        result = _engine_factory().remediate(
            Finding.model_validate(body["finding"]),
            str(body["action"]),
            str(body["actor"]),
            body.get("parameters", {}),
            approval_id=UUID(approval_id) if approval_id else None,
            dry_run=dry_run,
        )
        status = 200 if result.executed or result.dry_run else 403
        logger.info("azure_remediation_function_completed finding_id=%s", result.finding_id)
        return {"status_code": status, "json": result.model_dump(mode="json")}
    except (KeyError, TypeError, ValueError) as exc:
        logger.warning("azure_remediation_function_invalid_request type=%s", type(exc).__name__)
        return {"status_code": 400, "json": {"error": "Invalid remediation request"}}
    except Exception as exc:
        logger.exception("azure_remediation_function_failed")
        return {
            "status_code": 500,
            "json": {"error": "Remediation request failed", "type": type(exc).__name__},
        }
