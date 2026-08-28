"""Application factory and local entry point."""

import logging

import uvicorn
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

from cloud_security_governance import __version__
from cloud_security_governance.api import router
from cloud_security_governance.config import get_settings
from cloud_security_governance.exceptions import CloudSecurityError
from cloud_security_governance.logging import configure_logging


def create_app() -> FastAPI:
    settings = get_settings()
    configure_logging(settings.log_level)
    application = FastAPI(title=settings.app_name, version=__version__)
    application.include_router(router)

    @application.exception_handler(CloudSecurityError)
    async def handle_application_error(
        request: Request, exc: CloudSecurityError
    ) -> JSONResponse:
        logging.getLogger(__name__).warning(
            "Application error on %s: %s", request.url.path, exc
        )
        return JSONResponse(status_code=500, content={"detail": "Application error"})

    return application


app = create_app()


def run() -> None:
    uvicorn.run("cloud_security_governance.main:app", host="127.0.0.1", port=8000)


if __name__ == "__main__":
    run()

