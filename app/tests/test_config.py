import pytest
from pydantic import ValidationError

from secure_api.core.config import Settings


@pytest.mark.parametrize(
    "options",
    [
        {"APP_ENV": "production"},
        {"auth_enabled": True},
        {"keyvault_enabled": True},
        {"cors_origins": ["*"]},
        {"cors_origins": ["https://example.com/path"]},
        {"cors_origins": ["https://user:password@example.com"]},
        {"cors_origins": ["https://*.example.com"]},
        {"keyvault_url": "http://safe.vault.azure.net"},
        {"keyvault_url": "https://attacker.example.com"},
        {"keyvault_url": "https://safe.vault.azure.net.evil.com"},
        {"keyvault_url": "https://safe.vault.azure.net:8443"},
        {"keyvault_url": "https://safe.vault.azure.net?secret=data"},
        {"required_scopes": [""]},
        {"required_roles": ["bad role"]},
        {"workers": 0},
        {"workers": 9},
        {"limit_concurrency": 0},
        {"entra_tenant_id": "common"},
        {"APP_ENV": "invalid"},
    ],
)
def test_invalid_configuration(options):
    with pytest.raises(ValidationError):
        Settings(**options)


def test_production_configuration(settings):
    valid = settings.model_dump(exclude={"environment"})
    valid.update(APP_ENV="production", cors_origins=["https://app.example.com"])
    assert Settings(**valid).environment == "production"
    for change in [
        {"docs_enabled": True},
        {"required_scopes": [], "required_roles": []},
        {"cors_origins": ["http://app.example.com"]},
    ]:
        with pytest.raises(ValidationError):
            Settings(**(valid | change))


def test_environment_and_vault_normalization(monkeypatch):
    monkeypatch.setenv("APP_WORKERS", "2")
    monkeypatch.setenv("APP_ENV", "test")
    config = Settings(keyvault_enabled=True, keyvault_url="https://safe.vault.azure.net/")
    assert config.workers == 2
    assert config.environment == "test"
    assert config.keyvault_url == "https://safe.vault.azure.net"
