"""Application factory and local entry point."""

import logging

import uvicorn
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

from cloud_security_governance import __version__
from cloud_security_governance.api import router
from cloud_security_governance.api_service import GovernanceAPIService
from cloud_security_governance.auth import TokenAuthenticator
from cloud_security_governance.config import get_settings
from cloud_security_governance.exceptions import CloudSecurityError
from cloud_security_governance.logging import configure_logging


def create_app(
    api_service: GovernanceAPIService | None = None,
    authenticator: TokenAuthenticator | None = None,
) -> FastAPI:
    settings = get_settings()
    configure_logging(settings.log_level)
    application = FastAPI(title=settings.app_name, version=__version__)
    application.state.api_service = api_service
    application.state.authenticator = authenticator or TokenAuthenticator()
    application.include_router(router)

    @application.exception_handler(CloudSecurityError)
    async def handle_application_error(request: Request, exc: CloudSecurityError) -> JSONResponse:
        logging.getLogger(__name__).warning(
            "Application error path=%s type=%s", request.url.path, type(exc).__name__
        )
        return JSONResponse(status_code=500, content={"detail": "Application error"})

    @application.exception_handler(Exception)
    async def handle_unexpected_error(request: Request, exc: Exception) -> JSONResponse:
        logging.getLogger(__name__).error(
            "Unexpected application error path=%s type=%s",
            request.url.path,
            type(exc).__name__,
        )
        return JSONResponse(status_code=500, content={"detail": "Internal server error"})

    return application


app = create_app()


def run() -> None:
    uvicorn.run("cloud_security_governance.main:app", host="127.0.0.1", port=8000)


if __name__ == "__main__":
    run()
