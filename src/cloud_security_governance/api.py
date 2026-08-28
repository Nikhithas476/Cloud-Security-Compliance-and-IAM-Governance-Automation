"""FastAPI routes for service health and metadata."""

from fastapi import APIRouter
from pydantic import BaseModel

from cloud_security_governance import __version__
from cloud_security_governance.config import get_settings

router = APIRouter()


class HealthResponse(BaseModel):
    status: str
    service: str
    environment: str
    version: str


@router.get("/health", response_model=HealthResponse, tags=["system"])
def health() -> HealthResponse:
    settings = get_settings()
    return HealthResponse(
        status="ok",
        service=settings.app_name,
        environment=settings.app_env,
        version=__version__,
    )

