"""Azure provider integrations."""

from cloud_security_governance.azure.policy_scanner import AzurePolicyScanner
from cloud_security_governance.azure.rbac_scanner import AzureRBACRules, AzureRBACScanner
from cloud_security_governance.azure.scanner import AzureScanner
from cloud_security_governance.azure.storage_scanner import (
    AzureStorageEncryptionRules,
    AzureStorageEncryptionScanner,
)

__all__ = [
    "AzurePolicyScanner",
    "AzureRBACRules",
    "AzureRBACScanner",
    "AzureScanner",
    "AzureStorageEncryptionRules",
    "AzureStorageEncryptionScanner",
]
