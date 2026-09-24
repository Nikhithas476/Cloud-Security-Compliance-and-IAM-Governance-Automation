"""Thin Azure Function entry point for the compliance workflow."""

from __future__ import annotations

import logging
from collections.abc import Callable
from typing import Any

from cloud_security_governance.workflow import ComplianceWorkflowService

logger = logging.getLogger(__name__)
_workflow_factory: Callable[[], ComplianceWorkflowService] | None = None


def configure_workflow(factory: Callable[[], ComplianceWorkflowService]) -> None:
    global _workflow_factory
    _workflow_factory = factory


def main(request: Any) -> dict[str, Any]:
    del request
    try:
        if _workflow_factory is None:
            raise RuntimeError("The compliance workflow is not configured")
        result = _workflow_factory().run()
        payload = {
            "scan_id": str(result.scan.scan_id),
            "findings_count": len(result.scan.findings),
            "overall_risk_score": result.risk.overall_risk_score,
            "reports_generated": ["json", "csv", "html"],
        }
        logger.info("azure_scan_function_completed scan_id=%s", result.scan.scan_id)
        return {"status_code": 200, "json": payload}
    except Exception as exc:
        logger.exception("azure_scan_function_failed")
        return {
            "status_code": 500,
            "json": {"error": "Scan workflow failed", "type": type(exc).__name__},
        }
