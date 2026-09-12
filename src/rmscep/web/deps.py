"""Things the endpoints need from the running app

Its own module so the routers and the app factory do not import each other.
"""

import logging

from fastapi import Request

from ..scep import RaIdentity

LOGGER = logging.getLogger(__name__)


def get_ra(request: Request) -> RaIdentity:
    """The RA identity, loaded once before the workers start

    Devices encrypt their certificate request to this key, so it has to be the same one for the
    whole deployment and it has to exist before anything is served.
    """
    identity = getattr(request.app.state, "ra_identity", None)
    if identity is None:  # pragma: no cover -- the lifespan always sets it
        raise RuntimeError("RA identity was not loaded")
    return identity  # type: ignore[no-any-return]
