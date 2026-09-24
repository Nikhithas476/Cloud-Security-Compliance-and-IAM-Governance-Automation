"""Persistence interfaces and implementations."""

from cloud_security_governance.storage.base import FindingStorage
from cloud_security_governance.storage.dynamodb import DynamoDBStorage

__all__ = ["DynamoDBStorage", "FindingStorage"]
