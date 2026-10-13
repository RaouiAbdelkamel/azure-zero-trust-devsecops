"""Explicit non-secret configuration. Environment files are never loaded implicitly."""

from typing import Literal
from urllib.parse import urlsplit
from uuid import UUID

from pydantic import Field, field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="APP_", extra="forbid", frozen=True)

    environment: Literal["development", "test", "production"] = Field(
        default="development", validation_alias="APP_ENV"
    )
    auth_enabled: bool = False
    docs_enabled: bool = False
    entra_tenant_id: UUID | None = None
    entra_audience: UUID | None = None
    required_scopes: list[str] = Field(default_factory=lambda: ["api.read"])
    required_roles: list[str] = Field(default_factory=list)
    cors_origins: list[str] = Field(default_factory=list)
    hsts_enabled: bool = False
    keyvault_enabled: bool = False
    keyvault_url: str | None = None
    workers: int = Field(default=1, ge=1, le=8)
    keep_alive_seconds: int = Field(default=5, ge=1, le=60)
    graceful_shutdown_seconds: int = Field(default=20, ge=1, le=120)
    limit_concurrency: int = Field(default=100, ge=1, le=10000)

    @field_validator("required_scopes", "required_roles")
    @classmethod
    def permission_names(cls, values: list[str]) -> list[str]:
        if any(
            not value or len(value) > 128 or any(c.isspace() for c in value) for value in values
        ):
            raise ValueError("Permissions must be nonempty names without whitespace")
        return values

    @field_validator("cors_origins")
    @classmethod
    def explicit_origins(cls, values: list[str]) -> list[str]:
        for value in values:
            parts = urlsplit(value)
            if (
                parts.scheme not in {"https", "http"}
                or not parts.hostname
                or parts.username
                or parts.password
                or parts.path
                or parts.query
                or parts.fragment
                or "*" in value
            ):
                raise ValueError("CORS requires exact HTTP(S) origins, without paths or wildcards")
        return values

    @field_validator("keyvault_url")
    @classmethod
    def azure_vault_only(cls, value: str | None) -> str | None:
        if value is None:
            return None
        parts = urlsplit(value)
        if (
            parts.scheme != "https"
            or not parts.hostname
            or not parts.hostname.endswith(".vault.azure.net")
            or parts.hostname.count(".") != 3
            or parts.port not in {None, 443}
            or parts.username
            or parts.password
            or parts.path not in {"", "/"}
            or parts.query
            or parts.fragment
        ):
            raise ValueError("Only Azure public-cloud Key Vault HTTPS endpoints are allowed")
        return value.rstrip("/")

    @model_validator(mode="after")
    def consistent_security(self) -> "Settings":
        if self.environment == "production" and (not self.auth_enabled or self.docs_enabled):
            raise ValueError("Production requires authentication and disables API documentation")
        if self.auth_enabled and (
            not self.entra_tenant_id
            or not self.entra_audience
            or not (self.required_scopes or self.required_roles)
        ):
            raise ValueError("Authentication requires tenant, audience and scopes or roles")
        if self.keyvault_enabled and not self.keyvault_url:
            raise ValueError("Key Vault requires a vault URL")
        if self.environment == "production" and any(
            not origin.startswith("https://") for origin in self.cors_origins
        ):
            raise ValueError("Production CORS origins require HTTPS")
        return self

    @property
    def issuer(self) -> str:
        return f"https://login.microsoftonline.com/{self.entra_tenant_id}/v2.0"

    @property
    def jwks_url(self) -> str:
        return f"https://login.microsoftonline.com/{self.entra_tenant_id}/discovery/v2.0/keys"
