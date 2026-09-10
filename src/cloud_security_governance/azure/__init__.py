"""Azure provider integrations."""

from cloud_security_governance.azure.rbac_scanner import AzureRBACRules, AzureRBACScanner
from cloud_security_governance.azure.scanner import AzureScanner

__all__ = ["AzureRBACRules", "AzureRBACScanner", "AzureScanner"]
