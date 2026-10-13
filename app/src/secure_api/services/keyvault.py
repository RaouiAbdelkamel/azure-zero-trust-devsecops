"""Lazy Key Vault access using exclusively federated/managed identity credentials."""

import os
import re
from typing import Any, Protocol

from azure.core.exceptions import AzureError
from azure.identity import DefaultAzureCredential
from azure.keyvault.secrets import SecretClient

from secure_api.core.config import Settings


class SecretReader(Protocol):
    def get_secret(self, name: str, **kwargs: Any) -> Any: ...
    def close(self) -> None: ...


class KeyVaultUnavailable(RuntimeError):
    """Generic application error; original SDK exception must never be returned/logged."""


def identity_credential(settings: Settings) -> DefaultAzureCredential:
    if (
        os.getenv("AZURE_CLIENT_SECRET")
        or os.getenv("AZURE_CLIENT_CERTIFICATE_PATH")
        or os.getenv("AZURE_TOKEN_CREDENTIALS")
    ):
        raise KeyVaultUnavailable("Permanent Azure credentials are prohibited")
    if settings.environment == "production" and not all(
        os.getenv(name)
        for name in ("AZURE_CLIENT_ID", "AZURE_TENANT_ID", "AZURE_FEDERATED_TOKEN_FILE")
    ):
        raise KeyVaultUnavailable("Workload Identity is not configured")
    # Pas de fallback IMDS en production : éviter l'usurpation de l'identité du nœud AKS.
    return DefaultAzureCredential(
        authority="login.microsoftonline.com",
        exclude_environment_credential=True,
        exclude_managed_identity_credential=settings.environment == "production",
        exclude_shared_token_cache_credential=True,
        exclude_visual_studio_code_credential=True,
        exclude_cli_credential=True,
        exclude_powershell_credential=True,
        exclude_developer_cli_credential=True,
        exclude_interactive_browser_credential=True,
        exclude_broker_credential=True,
        logging_enable=False,
    )


class KeyVaultService:
    def __init__(self, settings: Settings, client: SecretReader | None = None):
        self.settings = settings
        self.client = client
        self.credential: DefaultAzureCredential | None = None

    def get_secret(self, name: str) -> str:
        if not re.fullmatch(r"[a-zA-Z0-9-]{1,127}", name):
            raise ValueError("Invalid secret name")
        if not self.settings.keyvault_enabled:
            raise KeyVaultUnavailable("Key Vault is disabled")
        try:
            if self.client is None:
                self.credential = identity_credential(self.settings)
                self.client = SecretClient(
                    vault_url=self.settings.keyvault_url,
                    credential=self.credential,
                    connection_timeout=5,
                    read_timeout=5,
                    retry_total=2,
                    logging_enable=False,
                )
            value = self.client.get_secret(name, logging_enable=False).value
            if value is None:
                raise KeyVaultUnavailable("Secret unavailable")
            return value
        except AzureError:
            raise KeyVaultUnavailable("Secret unavailable") from None

    def close(self) -> None:
        if self.client is not None:
            self.client.close()
        if self.credential is not None:
            self.credential.close()
