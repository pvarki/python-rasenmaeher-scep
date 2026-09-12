"""Health check"""

import logging

from fastapi import APIRouter, Request
from libpvarki.schemas.product import ProductHealthCheckResponse

from .. import config
from .deps import get_ra

LOGGER = logging.getLogger(__name__)

hrouter = APIRouter()


@hrouter.get("/healthcheck")
async def request_healthcheck(request: Request) -> ProductHealthCheckResponse:
    """Check that we are healthy, return accordingly

    Deliberately about ourselves only. Probing RASENMAEHER from here would make an unhealthy
    RASENMAEHER restart this container, and in compose the autoheal watcher would happily do that
    on every flap.
    """
    broken = []
    notes = []
    try:
        identity = get_ra(request)
        notes.append(f"RA serial {identity.cert.serial_number}")
    except RuntimeError:
        broken.append("RA identity is not loaded")
    if not config.CA_CHAIN_PATH.is_file():
        broken.append(f"CA chain {config.CA_CHAIN_PATH} is missing")

    # Not being configured to enrol anything is a deployment that has not turned this on yet, not
    # a service that is failing. Saying otherwise would have the compose autoheal watcher restart
    # a perfectly functioning container for ever. It is reported, and logged loudly at startup.
    if not config.CHALLENGE:
        notes.append("no challenge set, enrolment refused")
    if not config.RMAPI_URL:
        notes.append("no RASENMAEHER URL set, enrolment refused")

    if broken:
        return ProductHealthCheckResponse(healthy=False, extra=", ".join(broken))
    return ProductHealthCheckResponse(healthy=True, extra=", ".join(notes))
