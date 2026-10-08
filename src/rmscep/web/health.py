"""Health check"""

import datetime
import logging

from cryptography import x509
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
    broken_identity, identity_note = _client_identity_state()
    broken.extend(broken_identity)
    notes.extend(identity_note)

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


#: How close to expiry the client certificate may get before the healthcheck says so
RENEW_WARN_DAYS = 14


def _client_identity_state() -> tuple[list[str], list[str]]:
    """What our own client certificate is doing, as (broken, notes)

    Without it we cannot complete a single enrolment, so an expired or unreadable one is not
    healthy. Having none at all is different: in a meshed deployment the mesh presents our
    identity and there is nothing here to load.
    """
    if not config.CERT or not config.KEY:
        return [], ["no client certificate configured, identity comes from the mesh"]
    if not config.CERT.is_file() or not config.KEY.is_file():
        return [f"client certificate {config.CERT} is missing"], []
    try:
        cert = x509.load_pem_x509_certificate(config.CERT.read_bytes())
    except (ValueError, OSError) as exc:
        return [f"client certificate {config.CERT} does not parse: {exc}"], []
    left = cert.not_valid_after_utc - datetime.datetime.now(datetime.UTC)
    if left.total_seconds() <= 0:
        return [f"client certificate expired {-left.days}d ago"], []
    if left.days <= RENEW_WARN_DAYS:
        return [], [f"client certificate expires in {left.days}d"]
    return [], [f"client certificate valid {left.days}d"]
