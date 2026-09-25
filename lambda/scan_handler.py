"""Thin AWS Lambda adapter for the existing compliance workflow."""

from __future__ import annotations

import json
import logging
from collections.abc import Callable
from typing import Any

from cloud_security_governance.bootstrap import get_workflow_service
from cloud_security_governance.workflow import ComplianceWorkflowService

logger = logging.getLogger(__name__)
_workflow_factory: Callable[[], ComplianceWorkflowService] = get_workflow_service


def configure_workflow(factory: Callable[[], ComplianceWorkflowService]) -> None:
    global _workflow_factory
    _workflow_factory = factory


def lambda_handler(event: dict[str, Any], context: Any) -> dict[str, Any]:
    del event, context
    try:
        result = _workflow_factory().run()
        payload = {
            "scan_id": str(result.scan.scan_id),
            "findings_count": len(result.scan.findings),
            "overall_risk_score": result.risk.overall_risk_score,
            "reports_generated": ["json", "csv", "html"],
        }
        logger.info("scan_lambda_completed %s", json.dumps(payload, sort_keys=True))
        return {"statusCode": 200, "body": json.dumps(payload)}
    except Exception as exc:
        logger.exception("scan_lambda_failed")
        return {
            "statusCode": 500,
            "body": json.dumps({"error": "Scan workflow failed", "type": type(exc).__name__}),
        }
