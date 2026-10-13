"""App factory and production ASGI launcher; no filesystem writes or Azure startup calls."""

import logging
from contextlib import asynccontextmanager
from time import perf_counter
from uuid import uuid4

import uvicorn
from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware

from secure_api.api.routes import router
from secure_api.core.config import Settings
from secure_api.core.logging import configure_logging, event
from secure_api.core.security import TokenVerifier
from secure_api.services.keyvault import KeyVaultService


class SecurityMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        start = perf_counter()
        # Generate locally: user-controlled request IDs are never trusted or logged.
        request_id = str(uuid4())
        request.state.request_id = request_id
        try:
            response = await call_next(request)
        except Exception:
            # Never include exception repr, traceback, headers, body or query string.
            response = JSONResponse({"detail": "Internal server error"}, status_code=500)
        response.headers.update(
            {
                "X-Request-ID": request_id,
                "X-Content-Type-Options": "nosniff",
                "Referrer-Policy": "no-referrer",
                "Cache-Control": "no-store",
                "Content-Security-Policy": "default-src 'none'; frame-ancestors 'none'",
            }
        )
        if request.app.state.settings.hsts_enabled and request.url.scheme == "https":
            response.headers["Strict-Transport-Security"] = "max-age=31536000"
        route = request.scope.get("route")
        endpoint = getattr(route, "path", "unmatched")  # No user-controlled 404 path in logs.
        event(
            logging.INFO,
            event="http_request",
            request_id=request_id,
            endpoint=endpoint,
            status=response.status_code,
            duration_ms=round((perf_counter() - start) * 1000, 3),
        )
        return response


def create_app(
    settings: Settings | None = None,
    verifier: TokenVerifier | None = None,
    keyvault: KeyVaultService | None = None,
) -> FastAPI:
    settings = settings or Settings()
    configure_logging()
    vault = keyvault or KeyVaultService(settings)

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        app.state.ready = True
        try:
            yield
        finally:
            app.state.ready = False
            vault.close()

    app = FastAPI(
        title="Secure API",
        version="1.0.0",
        lifespan=lifespan,
        debug=False,
        docs_url="/docs" if settings.docs_enabled else None,
        redoc_url=None,
        openapi_url="/openapi.json" if settings.docs_enabled else None,
    )
    app.state.settings = settings
    app.state.ready = False
    app.state.verifier = verifier or TokenVerifier(settings) if settings.auth_enabled else None
    app.state.keyvault = vault
    app.include_router(router)
    if settings.cors_origins:
        app.add_middleware(
            CORSMiddleware,
            allow_origins=settings.cors_origins,
            allow_credentials=False,
            allow_methods=["GET"],
            allow_headers=["Authorization", "Content-Type"],
        )
    # Outermost: headers/logging also cover CORS preflight responses and failures.
    app.add_middleware(SecurityMiddleware)

    @app.exception_handler(RequestValidationError)
    async def invalid_input(request: Request, exc: RequestValidationError):
        return JSONResponse({"detail": "Invalid request"}, status_code=422)

    return app


def run() -> None:
    settings = Settings()
    uvicorn.run(
        "secure_api.main:create_app",
        factory=True,
        # Binding required inside a container; NSG/NetworkPolicy control external reachability.
        host="0.0.0.0",  # noqa: S104  # nosec B104
        port=8080,
        workers=settings.workers,
        reload=False,
        access_log=False,
        proxy_headers=False,
        server_header=False,
        timeout_keep_alive=settings.keep_alive_seconds,
        timeout_graceful_shutdown=settings.graceful_shutdown_seconds,
        limit_concurrency=settings.limit_concurrency,
        backlog=128,
        log_level="warning",
    )


if __name__ == "__main__":
    run()
