"""Domain-specific exceptions."""


class CloudSecurityError(Exception):
    """Base exception for expected application failures."""


class ConfigurationError(CloudSecurityError):
    """Raised when application configuration cannot be loaded or validated."""


class CloudProviderError(CloudSecurityError):
    """Raised when a cloud provider operation fails."""


class GovernanceError(CloudSecurityError):
    """Raised when an IAM governance operation fails."""

