"""AWS Lambda entry point placeholder; cloud scanning is intentionally absent."""

from typing import Any


def handler(event: dict[str, Any], context: Any) -> dict[str, Any]:
    del event, context
    return {"statusCode": 200, "body": "Service foundation is ready"}

