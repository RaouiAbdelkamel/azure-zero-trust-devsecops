from unittest.mock import Mock

from fastapi.testclient import TestClient

from secure_api.core.config import Settings
from secure_api.main import create_app


def test_health_without_azure():
    vault = Mock()
    app = create_app(Settings(APP_ENV="test"), keyvault=vault)
    with TestClient(app) as client:
        assert client.get("/health/live").json() == {"status": "alive"}
        assert client.get("/health/ready").json() == {"status": "ready"}
        assert client.get("/api/v1/info").json() == {
            "service": "secure-api",
            "version": "1.0.0",
            "environment": "test",
        }
        app.state.ready = False
        response = client.get("/health/ready")
        assert response.status_code == 503
        assert response.json() == {"status": "not_ready"}
        assert client.get("/health/live").status_code == 200
        vault.get_secret.assert_not_called()
    assert not app.state.ready
    vault.close.assert_called_once()


def test_documentation_disabled():
    with TestClient(create_app(Settings(APP_ENV="test"))) as client:
        for path in ("/docs", "/redoc", "/openapi.json"):
            assert client.get(path).status_code == 404


def test_documentation_explicit_development():
    with TestClient(create_app(Settings(docs_enabled=True))) as client:
        assert client.get("/docs").status_code == 200
        assert client.get("/openapi.json").status_code == 200


def test_launcher_has_safe_options(monkeypatch):
    from secure_api import main

    launcher = Mock()
    monkeypatch.setattr(main.uvicorn, "run", launcher)
    main.run()
    options = launcher.call_args.kwargs
    assert options["port"] == 8080
    assert not options["reload"]
    assert not options["access_log"]
    assert not options["proxy_headers"]
    assert options["timeout_graceful_shutdown"] == 20
