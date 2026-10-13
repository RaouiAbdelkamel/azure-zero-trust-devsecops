"""Single-tenant Entra v2 access tokens. Never trust token-selected URLs or algorithms."""

from typing import Annotated, Any, Protocol

import jwt
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey
from fastapi import Depends, HTTPException, Request
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from jwt import PyJWK, PyJWKClient
from jwt.exceptions import PyJWKClientConnectionError, PyJWKClientError

from secure_api.core.config import Settings


class KeyProvider(Protocol):
    def get_signing_key_from_jwt(self, token: str) -> PyJWK: ...


class TokenVerifier:
    def __init__(self, settings: Settings, key_provider: KeyProvider | None = None):
        self.settings = settings
        self.keys = key_provider or PyJWKClient(
            settings.jwks_url, timeout=5, lifespan=300, cache_keys=False, cooldown_duration=30
        )

    def verify(self, token: str) -> None:
        try:
            if len(token) > 16384:
                raise jwt.InvalidTokenError("Oversized token")
            header = jwt.get_unverified_header(token)  # Selection only; signature verified below.
            if (
                header.get("alg") != "RS256"
                or not isinstance(header.get("kid"), str)
                or not 1 <= len(header["kid"]) <= 128
                or any(name in header for name in ("jku", "x5u", "crit"))
            ):
                raise jwt.InvalidTokenError("Unsupported header")
            key = self.keys.get_signing_key_from_jwt(token)
            if (
                key.algorithm_name != "RS256"
                or not isinstance(key.key, RSAPublicKey)
                or key.key.key_size < 2048
                or key.public_key_use not in {None, "sig"}
            ):
                raise jwt.InvalidTokenError("Unsupported signing key")
            # Microsoft may attach an issuer template to a tenant-independent key.
            key_issuer = key._jwk_data.get("issuer")
            if key_issuer is not None and (
                not isinstance(key_issuer, str)
                or key_issuer.replace("{tenantid}", str(self.settings.entra_tenant_id))
                != self.settings.issuer
            ):
                raise jwt.InvalidTokenError("Key issuer mismatch")
            claims = jwt.decode(
                token,
                key.key,
                algorithms=["RS256"],
                audience=str(self.settings.entra_audience),
                issuer=self.settings.issuer,
                leeway=0,
                options={
                    "require": ["exp", "iat", "nbf", "iss", "aud", "sub", "tid", "ver"],
                    "strict_aud": True,
                },
            )
            if claims["tid"] != str(self.settings.entra_tenant_id) or claims["ver"] != "2.0":
                raise jwt.InvalidTokenError("Tenant or token version mismatch")
            self._authorize(claims)
        except PyJWKClientConnectionError as exc:
            raise HTTPException(503, "Authentication service unavailable") from exc
        except (jwt.InvalidTokenError, PyJWKClientError, ValueError, TypeError) as exc:
            raise HTTPException(
                401, "Invalid access token", headers={"WWW-Authenticate": "Bearer"}
            ) from exc

    def _authorize(self, claims: dict[str, Any]) -> None:
        scope_claim = claims.get("scp", "")
        role_claim = claims.get("roles", [])
        if (
            not isinstance(scope_claim, str)
            or not isinstance(role_claim, list)
            or any(not isinstance(role, str) for role in role_claim)
        ):
            raise jwt.InvalidTokenError("Invalid permission claims")
        scopes = set(scope_claim.split())
        roles = set(role_claim)
        # Toutes les exigences configurées doivent être présentes, y compris les deux
        # catégories si scopes ET roles sont configurés. Jamais de fallback permissif.
        if (
            not set(self.settings.required_scopes) <= scopes
            or not set(self.settings.required_roles) <= roles
        ):
            raise HTTPException(403, "Insufficient permissions")


bearer = HTTPBearer(auto_error=False)


def require_identity(
    request: Request,
    credentials: Annotated[HTTPAuthorizationCredentials | None, Depends(bearer)],
) -> None:
    verifier = request.app.state.verifier
    if verifier is None:
        raise HTTPException(503, "Authentication is not configured")
    if credentials is None:
        raise HTTPException(401, "Access token required", headers={"WWW-Authenticate": "Bearer"})
    verifier.verify(credentials.credentials)
