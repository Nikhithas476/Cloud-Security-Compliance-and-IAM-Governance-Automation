"""Deployment exports for the scan and remediation Azure Functions."""

from azure_functions.remediation_function import main as remediation
from azure_functions.scan_function import main as scan

__all__ = ["remediation", "scan"]
