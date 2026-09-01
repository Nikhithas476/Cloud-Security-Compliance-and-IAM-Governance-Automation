"""Domain-specific exceptions."""


class CloudSecurityError(Exception):
    """Base exception for expected application failures."""


class ConfigurationError(CloudSecurityError):
    """Raised when application configuration cannot be loaded or validated."""


class CloudProviderError(CloudSecurityError):
    """Raised when a cloud provider operation fails."""


class AWSScannerError(CloudProviderError):
    """Base exception for expected AWS scanner failures."""


class AWSConfigurationError(AWSScannerError):
    """Raised when AWS scanner configuration is invalid."""


class AWSAuthenticationError(AWSScannerError):
    """Raised when AWS credentials or STS authentication cannot be validated."""


class GovernanceError(CloudSecurityError):
    """Raised when an IAM governance operation fails."""
