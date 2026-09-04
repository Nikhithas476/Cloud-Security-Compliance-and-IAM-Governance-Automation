"""AWS provider integrations."""

from cloud_security_governance.aws.audit_services_scanner import AWSCloudTrailConfigScanner
from cloud_security_governance.aws.encryption_scanner import AWSEncryptionScanner
from cloud_security_governance.aws.iam_scanner import AWSIAMScanner
from cloud_security_governance.aws.scanner import AWSCallerIdentity, AWSScanner

__all__ = [
    "AWSCallerIdentity",
    "AWSCloudTrailConfigScanner",
    "AWSEncryptionScanner",
    "AWSIAMScanner",
    "AWSScanner",
]
