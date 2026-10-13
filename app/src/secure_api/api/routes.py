"""No infrastructure identifiers or secret material in API responses."""

from typing import Literal

from fastapi import APIRouter, Depends, Request, Response
from pydantic import BaseModel

from secure_api import __version__
from secure_api.core.security import require_identity

router = APIRouter()


class LiveResponse(BaseModel):
    status: Literal["alive"] = "alive"


class ReadyResponse(BaseModel):
    status: Literal["ready", "not_ready"]


class InfoResponse(BaseModel):
    service: Literal["secure-api"] = "secure-api"
    version: str = __version__
    environment: Literal["development", "test", "production"]


class SecureResponse(BaseModel):
    status: Literal["authorized"] = "authorized"


@router.get("/health/live", response_model=LiveResponse)
def live() -> LiveResponse:
    return LiveResponse()


@router.get("/health/ready", response_model=ReadyResponse)
def ready(request: Request, response: Response) -> ReadyResponse:
    if not request.app.state.ready:
        response.status_code = 503
        return ReadyResponse(status="not_ready")
    return ReadyResponse(status="ready")


@router.get("/api/v1/info", response_model=InfoResponse)
def info(request: Request) -> InfoResponse:
    return InfoResponse(environment=request.app.state.settings.environment)


@router.get(
    "/api/v1/secure", response_model=SecureResponse, dependencies=[Depends(require_identity)]
)
def secure() -> SecureResponse:
    return SecureResponse()
