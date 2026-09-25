from types import SimpleNamespace
from unittest.mock import Mock

import pytest

from cloud_security_governance import bootstrap
from cloud_security_governance.exceptions import ConfigurationError
from cloud_security_governance.models import CloudProvider


def test_production_runtime_composes_aws_services(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("CLOUD_PROVIDERS", "aws")
    monkeypatch.setenv("STORAGE_BACKEND", "dynamodb")
    storage = Mock()
    monkeypatch.setattr(bootstrap, "DynamoDBStorage", Mock(return_value=storage))
    session = Mock()
    scanner = SimpleNamespace(provider=CloudProvider.AWS, _session=session)
    monkeypatch.setattr(bootstrap, "AWSScanner", Mock(return_value=scanner))
    monkeypatch.setattr(bootstrap, "DisableStaleAccessKeyExecutor", Mock(return_value=Mock()))
    monkeypatch.setattr(bootstrap, "RemovePolicyPermissionExecutor", Mock(return_value=Mock()))
    bootstrap.get_runtime.cache_clear()

    runtime = bootstrap.get_runtime()

    assert runtime.api.storage is storage
    assert runtime.workflow.scanner.scanners == (scanner,)
    assert runtime.remediation.approvals._repository is storage
    session.client.assert_called_once_with("iam", region_name="us-east-1")
    bootstrap.get_runtime.cache_clear()


def test_bootstrap_rejects_invalid_provider_or_storage(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("CLOUD_PROVIDERS", "gcp")
    with pytest.raises(ConfigurationError, match="only aws and azure"):
        bootstrap._providers()
    monkeypatch.setenv("STORAGE_BACKEND", "filesystem")
    with pytest.raises(ConfigurationError, match="dynamodb or azure_blob"):
        bootstrap._storage()
