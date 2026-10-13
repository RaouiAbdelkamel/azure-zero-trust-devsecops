"""Test keys generated in memory; all network connections forbidden in unit tests."""

import ipaddress
import json
import socket
from datetime import UTC, datetime
from unittest.mock import Mock
from uuid import UUID

import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa
from jwt import PyJWK

from secure_api.core.config import Settings
from secure_api.core.security import TokenVerifier

TENANT = "11111111-1111-1111-1111-111111111111"
AUDIENCE = "22222222-2222-2222-2222-222222222222"


@pytest.fixture(autouse=True)
def no_network(monkeypatch):
    original_connect = socket.socket.connect

    def forbidden(sock, address):
        # Windows asyncio creates its internal self-pipe using loopback sockets.
        if isinstance(address, tuple):
            try:
                if ipaddress.ip_address(address[0]).is_loopback:
                    return original_connect(sock, address)
            except ValueError:
                pass
        raise AssertionError("Network calls forbidden in unit tests")

    monkeypatch.setattr(socket.socket, "connect", forbidden)
    for name in [
        "AZURE_CLIENT_SECRET",
        "AZURE_CLIENT_CERTIFICATE_PATH",
        "AZURE_TOKEN_CREDENTIALS",
        "AZURE_CLIENT_ID",
        "AZURE_TENANT_ID",
        "AZURE_FEDERATED_TOKEN_FILE",
    ]:
        monkeypatch.delenv(name, raising=False)


@pytest.fixture
def settings():
    return Settings(
        APP_ENV="test",
        auth_enabled=True,
        entra_tenant_id=UUID(TENANT),
        entra_audience=UUID(AUDIENCE),
    )


@pytest.fixture(scope="session")
def signing_key():
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


@pytest.fixture
def provider(signing_key, settings):
    data = json.loads(jwt.algorithms.RSAAlgorithm.to_jwk(signing_key.public_key()))
    data.update(kid="test-key", use="sig", alg="RS256", issuer=settings.issuer)
    provider = Mock()
    provider.get_signing_key_from_jwt.return_value = PyJWK(data)
    return provider


@pytest.fixture
def verifier(settings, provider):
    return TokenVerifier(settings, provider)


@pytest.fixture
def claims(settings):
    now = int(datetime.now(UTC).timestamp())
    return {
        "iss": settings.issuer,
        "aud": str(settings.entra_audience),
        "tid": str(settings.entra_tenant_id),
        "sub": "local-test-subject",
        "ver": "2.0",
        "iat": now - 5,
        "nbf": now - 5,
        "exp": now + 300,
        "scp": "api.read",
    }


@pytest.fixture
def token(signing_key, claims):
    return jwt.encode(claims, signing_key, algorithm="RS256", headers={"kid": "test-key"})
