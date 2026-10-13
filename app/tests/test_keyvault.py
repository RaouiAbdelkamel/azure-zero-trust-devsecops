from types import SimpleNamespace
from unittest.mock import Mock

import pytest
from azure.core.exceptions import ClientAuthenticationError, HttpResponseError, ServiceRequestError

from secure_api.core.config import Settings
from secure_api.services.keyvault import KeyVaultService, KeyVaultUnavailable, identity_credential


@pytest.fixture
def vault_settings():
    return Settings(
        APP_ENV="test", keyvault_enabled=True, keyvault_url="https://safe.vault.azure.net"
    )


def test_secret_internal_only(vault_settings):
    client = Mock()
    client.get_secret.return_value = SimpleNamespace(value="DO-NOT-EXPOSE")
    service = KeyVaultService(vault_settings, client)
    assert service.get_secret("application-setting") == "DO-NOT-EXPOSE"
    client.get_secret.assert_called_once_with("application-setting", logging_enable=False)
    service.close()
    client.close.assert_called_once()


@pytest.mark.parametrize(
    "exception",
    [
        ClientAuthenticationError("TOKEN-SECRET"),
        HttpResponseError("PRIVATE-INFO"),
        ServiceRequestError("INTERNAL-HOST"),
    ],
)
def test_sdk_errors_are_generic(exception, vault_settings):
    client = Mock()
    client.get_secret.side_effect = exception
    with pytest.raises(KeyVaultUnavailable) as error:
        KeyVaultService(vault_settings, client).get_secret("allowed-name")
    assert str(error.value) == "Secret unavailable"
    assert error.value.__suppress_context__


@pytest.mark.parametrize("name", ["../secret", "", "with space", "a" * 128])
def test_secret_name_validation(name, vault_settings):
    client = Mock()
    with pytest.raises(ValueError):
        KeyVaultService(vault_settings, client).get_secret(name)
    client.get_secret.assert_not_called()


def test_disabled_and_empty(vault_settings):
    with pytest.raises(KeyVaultUnavailable):
        KeyVaultService(Settings()).get_secret("allowed-name")
    client = Mock()
    client.get_secret.return_value = SimpleNamespace(value=None)
    with pytest.raises(KeyVaultUnavailable):
        KeyVaultService(vault_settings, client).get_secret("allowed-name")


def test_lazy_initialization_and_close(vault_settings, monkeypatch):
    from secure_api.services import keyvault

    credential = Mock()
    client = Mock()
    client.get_secret.return_value = SimpleNamespace(value="internal-value")
    factory = Mock(return_value=client)
    monkeypatch.setattr(keyvault, "identity_credential", Mock(return_value=credential))
    monkeypatch.setattr(keyvault, "SecretClient", factory)
    service = KeyVaultService(vault_settings)
    factory.assert_not_called()
    assert service.get_secret("setting") == "internal-value"
    service.get_secret("setting")
    factory.assert_called_once()
    service.close()
    credential.close.assert_called_once()


@pytest.mark.parametrize(
    "name", ["AZURE_CLIENT_SECRET", "AZURE_CLIENT_CERTIFICATE_PATH", "AZURE_TOKEN_CREDENTIALS"]
)
def test_permanent_credentials_rejected(name, monkeypatch):
    monkeypatch.setenv(name, "PROHIBITED")
    with pytest.raises(KeyVaultUnavailable):
        identity_credential(Settings())


def test_production_identity_no_fallback(settings, monkeypatch):
    from secure_api.services import keyvault

    config = settings.model_copy(update={"environment": "production"})
    with pytest.raises(KeyVaultUnavailable):
        identity_credential(config)
    for name in ["AZURE_CLIENT_ID", "AZURE_TENANT_ID", "AZURE_FEDERATED_TOKEN_FILE"]:
        monkeypatch.setenv(name, "public-test-value")
    factory = Mock()
    monkeypatch.setattr(keyvault, "DefaultAzureCredential", factory)
    identity_credential(config)
    options = factory.call_args.kwargs
    for name in [
        "environment",
        "managed_identity",
        "cli",
        "powershell",
        "developer_cli",
        "interactive_browser",
        "broker",
    ]:
        assert options[f"exclude_{name}_credential"] is True


def test_development_identity_managed_allowed(monkeypatch):
    from secure_api.services import keyvault

    factory = Mock()
    monkeypatch.setattr(keyvault, "DefaultAzureCredential", factory)
    identity_credential(Settings())
    assert factory.call_args.kwargs["exclude_managed_identity_credential"] is False
