"""Azure Functions Python v2 registrations for scan and remediation endpoints."""

import json
import os

import azure.functions as func

from azure_functions.remediation_function import main as remediation_handler
from azure_functions.scan_function import main as scan_handler

app = func.FunctionApp(http_auth_level=func.AuthLevel.FUNCTION)


def _response(result: dict) -> func.HttpResponse:
    return func.HttpResponse(
        json.dumps(result["json"]),
        status_code=result["status_code"],
        mimetype="application/json",
    )


@app.function_name(name="scan")
@app.route(route="scan", methods=["POST"])
def scan(request: func.HttpRequest) -> func.HttpResponse:
    if os.getenv("FUNCTION_ROLE", "scan").casefold() != "scan":
        return func.HttpResponse(status_code=404)
    return _response(scan_handler(request))


@app.function_name(name="remediation")
@app.route(route="remediation", methods=["POST"])
def remediation(request: func.HttpRequest) -> func.HttpResponse:
    if os.getenv("FUNCTION_ROLE", "scan").casefold() != "remediation":
        return func.HttpResponse(status_code=403)
    return _response(remediation_handler(request))
