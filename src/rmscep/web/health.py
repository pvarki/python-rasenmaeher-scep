"""Health check"""

import logging

from fastapi import APIRouter, Request
from libpvarki.schemas.product import ProductHealthCheckResponse

from .. import config
from .application import get_ra

LOGGER = logging.getLogger(__name__)

hrouter = APIRouter()


@hrouter.get("/healthcheck")
async def request_healthcheck(request: Request) -> ProductHealthCheckResponse:
    """Check that we are healthy, return accordingly

    Deliberately about ourselves only. Probing RASENMAEHER from here would make an unhealthy
    RASENMAEHER restart this container, and in compose the autoheal watcher would happily do that
    on every flap.
    """
    problems = []
    try:
        identity = get_ra(request)
        extra = f"RA serial {identity.cert.serial_number}"
    except RuntimeError:
        problems.append("RA identity is not loaded")
        extra = "no RA identity"
    if not config.CA_CHAIN_PATH.is_file():
        problems.append(f"CA chain {config.CA_CHAIN_PATH} is missing")
    if not config.CHALLENGE:
        problems.append("no challenge configured")
    if not config.RMAPI_URL:
        problems.append("no RASENMAEHER URL configured")
    if problems:
        return ProductHealthCheckResponse(healthy=False, extra=", ".join(problems))
    return ProductHealthCheckResponse(healthy=True, extra=extra)
