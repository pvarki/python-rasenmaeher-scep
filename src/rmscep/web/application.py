"""FastAPI entrypoint"""

import logging
from collections.abc import AsyncGenerator
from contextlib import asynccontextmanager

from fastapi import FastAPI
from libpvarki.logging import add_trace_and_audit, init_logging

from rmscep import __version__

from .. import config
from ..scep import RaIdentity
from .health import hrouter
from .scep_views import router as scep_router

LOGGER = logging.getLogger(__name__)


@asynccontextmanager
async def app_lifespan(app: FastAPI) -> AsyncGenerator[None, None]:
    """Load the RA identity before anything can be served

    Generating it here rather than on first use is deliberate. Several workers meeting an empty
    directory at the same time would each make their own key, the last writer would win, and most
    requests would then fail to decrypt anything. Run `rmscep init-ra` in the entrypoint so the
    file already exists by the time workers start.
    """
    app.state.ra_identity = RaIdentity.load_or_create(config.ra_dir())
    LOGGER.info("RA identity ready, serial %s", app.state.ra_identity.cert.serial_number)
    if not config.CHALLENGE:
        LOGGER.error("RMSCEP_CHALLENGE is not set, every enrolment will be refused")
    if not config.RMAPI_URL:
        LOGGER.error("RMSCEP_RMAPI_URL is not set, every enrolment will be refused")
    yield None
    LOGGER.debug("Cleanup")


def get_app_no_init() -> FastAPI:
    """Just get the app, do not init logging etc"""
    app = FastAPI(
        docs_url="/api/docs",
        openapi_url="/api/openapi.json",
        title="RASENMAEHER SCEP responder",
        lifespan=app_lifespan,
        version=__version__,
    )
    app.include_router(hrouter, prefix="/api/v1", tags=["health"])
    app.include_router(scep_router, prefix=config.SCEP_PATH, tags=["scep"])
    return app


def get_app() -> FastAPI:
    """Returns the FastAPI application."""
    add_trace_and_audit()
    init_logging(config.LOG_LEVEL)
    return get_app_no_init()
