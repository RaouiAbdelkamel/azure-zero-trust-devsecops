import json
import logging
from unittest.mock import Mock

import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa
from fastapi import HTTPException
from fastapi.testclient import TestClient
from jwt import PyJWK
from jwt.exceptions import PyJWKClientConnectionError, PyJWKClientError

from secure_api.core.config import Settings
from secure_api.core.logging import JsonFormatter
from secure_api.core.security import TokenVerifier
from secure_api.main import create_app


def test_valid_signed_token(verifier, token, settings):
    with TestClient(create_app(settings, verifier)) as client:
        response = client.get("/api/v1/secure", headers={"Authorization": f"Bearer {token}"})
        assert response.status_code == 200
        assert response.json() == {"status": "authorized"}
        assert token not in response.text
        assert str(settings.entra_tenant_id) not in response.text


@pytest.mark.parametrize(
    "changes",
    [
        {"exp": 1},
        {"aud": "different-audience"},
        {"iss": "https://evil.example"},
        {"tid": "33333333-3333-3333-3333-333333333333"},
        {"ver": "1.0"},
        {"nbf": 9999999999},
        {"iat": 9999999999},
        {"aud": ["different"]},
        {"scp": ["api.read"]},
        {"roles": "Administrator"},
        {"roles": [1]},
    ],
)
def test_invalid_claims(changes, claims, signing_key, verifier):
    token = jwt.encode(
        claims | changes, signing_key, algorithm="RS256", headers={"kid": "test-key"}
    )
    with pytest.raises(HTTPException) as error:
        verifier.verify(token)
    assert error.value.status_code == 401
    assert token not in error.value.detail


@pytest.mark.parametrize("missing", ["exp", "iat", "nbf", "iss", "aud", "sub", "tid", "ver"])
def test_required_claims(missing, claims, signing_key, verifier):
    del claims[missing]
    token = jwt.encode(claims, signing_key, algorithm="RS256", headers={"kid": "test-key"})
    with pytest.raises(HTTPException) as error:
        verifier.verify(token)
    assert error.value.status_code == 401


def test_invalid_signature(claims, verifier):
    other = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    token = jwt.encode(claims, other, algorithm="RS256", headers={"kid": "test-key"})
    with pytest.raises(HTTPException) as error:
        verifier.verify(token)
    assert error.value.status_code == 401


@pytest.mark.parametrize("algorithm", ["none", "HS256", "RS512"])
def test_algorithm_rejected_before_jwks(algorithm, signing_key, claims, verifier, provider):
    key = None if algorithm == "none" else "local-test-hmac-key-at-least-32-bytes"
    if algorithm == "RS512":
        key = signing_key
    token = jwt.encode(claims, key, algorithm=algorithm, headers={"kid": "test-key"})
    with pytest.raises(HTTPException) as error:
        verifier.verify(token)
    assert error.value.status_code == 401
    provider.get_signing_key_from_jwt.assert_not_called()


@pytest.mark.parametrize(
    "header", [{"jku": "https://evil.example"}, {"x5u": "bad"}, {"crit": []}, {"kid": ""}]
)
def test_untrusted_headers(header, signing_key, claims, verifier, provider):
    token = jwt.encode(claims, signing_key, algorithm="RS256", headers={"kid": "test-key"} | header)
    with pytest.raises(HTTPException) as error:
        verifier.verify(token)
    assert error.value.status_code == 401
    provider.get_signing_key_from_jwt.assert_not_called()


@pytest.mark.parametrize("token", ["broken", "x" * 16385])
def test_invalid_token_format(token, verifier):
    with pytest.raises(HTTPException) as error:
        verifier.verify(token)
    assert error.value.status_code == 401


@pytest.mark.parametrize("change", [{"scp": "api.write"}, {"scp": ""}, {"roles": []}])
def test_missing_permission(change, settings, provider, claims, signing_key):
    settings = settings.model_copy(update={"required_roles": ["API.Reader"]})
    token = jwt.encode(claims | change, signing_key, algorithm="RS256", headers={"kid": "test-key"})
    with pytest.raises(HTTPException) as error:
        TokenVerifier(settings, provider).verify(token)
    assert error.value.status_code == 403


def test_application_role_token(settings, provider, claims, signing_key):
    settings = settings.model_copy(update={"required_scopes": [], "required_roles": ["API.Reader"]})
    claims.pop("scp")
    claims["roles"] = ["API.Reader"]
    TokenVerifier(settings, provider).verify(
        jwt.encode(claims, signing_key, algorithm="RS256", headers={"kid": "test-key"})
    )


@pytest.mark.parametrize(
    "error,status",
    [
        (PyJWKClientConnectionError("PRIVATE SDK ERROR"), 503),
        (PyJWKClientError("UNKNOWN KID"), 401),
    ],
)
def test_jwks_fail_closed(error, status, provider, verifier, token):
    provider.get_signing_key_from_jwt.side_effect = error
    with pytest.raises(HTTPException) as caught:
        verifier.verify(token)
    assert caught.value.status_code == status
    assert "PRIVATE SDK ERROR" not in caught.value.detail


@pytest.mark.parametrize(
    "updates",
    [
        {"issuer": "https://evil.example"},
        {"issuer": 123},
        {"alg": "RS512"},
        {"use": "enc"},
    ],
)
def test_untrusted_jwk(updates, provider, token, verifier):
    data = dict(provider.get_signing_key_from_jwt.return_value._jwk_data) | updates
    provider.get_signing_key_from_jwt.return_value = PyJWK(data)
    with pytest.raises(HTTPException) as error:
        verifier.verify(token)
    assert error.value.status_code == 401


def test_weak_rsa_key(provider, verifier, token):
    weak = rsa.generate_private_key(public_exponent=65537, key_size=1024)  # noqa: S505 -- negative test proves weak keys are rejected
    data = json.loads(jwt.algorithms.RSAAlgorithm.to_jwk(weak.public_key()))
    provider.get_signing_key_from_jwt.return_value = PyJWK(data | {"alg": "RS256"})
    with pytest.raises(HTTPException) as error:
        verifier.verify(token)
    assert error.value.status_code == 401


def test_missing_authentication_and_disabled_auth(settings, verifier):
    with TestClient(create_app(settings, verifier)) as client:
        assert client.get("/api/v1/secure").status_code == 401
        assert (
            client.get("/api/v1/secure", headers={"Authorization": "Basic Zm9v"}).status_code == 401
        )
    with TestClient(create_app(Settings(APP_ENV="test"))) as client:
        assert client.get("/api/v1/secure").status_code == 503


def test_headers_https_and_proxy_spoofing():
    app = create_app(Settings(APP_ENV="test", hsts_enabled=True))
    with TestClient(app, base_url="https://testserver") as client:
        response = client.get("/health/live")
        assert response.headers["strict-transport-security"] == "max-age=31536000"
        assert response.headers["x-content-type-options"] == "nosniff"
        assert response.headers["referrer-policy"] == "no-referrer"
        assert response.headers["cache-control"] == "no-store"
        assert "default-src 'none'" in response.headers["content-security-policy"]
    with TestClient(app) as client:
        assert (
            "strict-transport-security"
            not in client.get("/health/live", headers={"X-Forwarded-Proto": "https"}).headers
        )


def test_cors():
    app = create_app(Settings(cors_origins=["https://trusted.example"]))
    with TestClient(app) as client:
        for origin, status in [("https://trusted.example", 200), ("https://evil.example", 400)]:
            response = client.options(
                "/api/v1/info",
                headers={
                    "Origin": origin,
                    "Access-Control-Request-Method": "GET",
                },
            )
            assert response.status_code == status
            assert response.headers["x-content-type-options"] == "nosniff"
            assert response.headers.get("access-control-allow-origin") != "*"


def test_logs_and_error_responses_do_not_leak(monkeypatch):
    from secure_api import main

    events = Mock()
    monkeypatch.setattr(main, "event", events)
    app = create_app(Settings(APP_ENV="test"))

    @app.get("/failure")
    def failure():
        raise RuntimeError("SECRET-IN-EXCEPTION")

    @app.get("/validated")
    def validated(value: int):
        return {"value": value}

    with TestClient(app) as client:
        response = client.get(
            "/failure?secret=QUERY-SECRET",
            headers={
                "Authorization": "Bearer PRIVATE-TOKEN",
                "Cookie": "SESSION-SECRET",
                "X-Request-ID": "USER-CONTROLLED",
            },
        )
        assert response.status_code == 500
        assert response.json() == {"detail": "Internal server error"}
        assert response.headers["x-request-id"] != "USER-CONTROLLED"
        invalid = client.get("/validated?value=CONFIDENTIAL")
        assert invalid.status_code == 422
        assert invalid.json() == {"detail": "Invalid request"}
        client.get("/UNKNOWN-SECRET?password=123")
    serialized = str(events.call_args_list)
    for secret in [
        "QUERY-SECRET",
        "PRIVATE-TOKEN",
        "SESSION-SECRET",
        "CONFIDENTIAL",
        "UNKNOWN-SECRET",
    ]:
        assert secret not in serialized
    assert "unmatched" in serialized


def test_formatter_allowlist():
    record = logging.LogRecord("test", logging.INFO, "", 0, "PRIVATE MESSAGE", (), None)
    record.audit = {"event": "safe", "token": "SECRET", "status": 200}
    result = JsonFormatter().format(record)
    assert "SECRET" not in result
    assert "PRIVATE MESSAGE" not in result
    assert json.loads(result)["status"] == 200
