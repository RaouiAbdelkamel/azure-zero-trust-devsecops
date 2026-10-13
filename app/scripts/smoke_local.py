"""Real loopback HTTP smoke test, independent of Azure and Docker."""

import http.client
import json
import os

# Fixed local Python command, no shell and no credential arguments.
import subprocess  # nosec B404
import sys
import time
from pathlib import Path


def run() -> None:
    app_root = Path(__file__).resolve().parents[1]
    environment = os.environ | {
        "PYTHONPATH": str(app_root / "src"),
        "PYTHONDONTWRITEBYTECODE": "1",
        "APP_ENV": "test",
        "APP_AUTH_ENABLED": "false",
        "APP_KEYVAULT_ENABLED": "false",
        "APP_DOCS_ENABLED": "false",
    }
    process = subprocess.Popen(  # noqa: S603  # nosec B603
        [
            sys.executable,
            "-m",
            "uvicorn",
            "secure_api.main:create_app",
            "--factory",
            "--host",
            "127.0.0.1",
            "--port",
            "8080",
            "--no-access-log",
            "--no-proxy-headers",
        ],
        cwd=app_root,
        env=environment,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    try:
        for _ in range(50):
            if process.poll() is not None:
                raise RuntimeError("Server did not start; check port 8080 and configuration")
            connection = http.client.HTTPConnection("127.0.0.1", 8080, timeout=2)
            try:
                connection.request("GET", "/health/ready")
                if connection.getresponse().status == 200:
                    break
            except OSError:
                time.sleep(0.1)
            finally:
                connection.close()
        else:
            raise RuntimeError("Server readiness timeout")
        results = []
        for path, expected in [
            ("/health/live", 200),
            ("/health/ready", 200),
            ("/api/v1/info", 200),
            ("/api/v1/secure", 503),
            ("/docs", 404),
        ]:
            connection = http.client.HTTPConnection("127.0.0.1", 8080, timeout=2)
            try:
                connection.request("GET", path)
                response = connection.getresponse()
                body = response.read()
                if response.status != expected or response.getheader("Cache-Control") != "no-store":
                    raise RuntimeError("Unexpected HTTP response")
                if path == "/health/live" and json.loads(body) != {"status": "alive"}:
                    raise RuntimeError("Unexpected liveness body")
                results.append({"endpoint": path, "status": response.status})
            finally:
                connection.close()
        (app_root / "reports").mkdir(exist_ok=True)
        (app_root / "reports/smoke.json").write_text(
            json.dumps(results, indent=2), encoding="utf-8"
        )
        print(json.dumps(results))
    finally:
        process.terminate()
        try:
            process.wait(timeout=10)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=5)


if __name__ == "__main__":
    run()
