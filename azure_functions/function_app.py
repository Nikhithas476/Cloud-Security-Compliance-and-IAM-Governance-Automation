"""Azure Functions entry-point placeholder; no cloud scanning is implemented."""

from typing import Any


def health(request: Any) -> dict[str, Any]:
    del request
    return {"status_code": 200, "body": "Service foundation is ready"}

