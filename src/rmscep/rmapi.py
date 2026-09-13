"""Talking to RASENMAEHER

One call, to one endpoint that already exists: complete a device enrolment an admin planned. We
authenticate with our own client certificate from the deployment CA, exactly as every other
container in the deployment does. We hold no token, no invite code and no admin identity, and the
only thing our CN is permitted to do is this.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from pathlib import Path

import httpx

from . import config

LOGGER = logging.getLogger(__name__)


class RmapiRefused(Exception):
    """RASENMAEHER said no, and meant it

    The device is asking for something it will not get by asking again: the callsign was never
    planned, or somebody else has it, or the request does not match. Tell the device so, rather
    than leaving the MDM to retry for ever.
    """


class RmapiUnavailable(Exception):
    """We could not get an answer

    Might work next time. The MDM will retry on its own schedule.
    """


@dataclass
class IssuedCertificate:
    """What came back"""

    callsign: str
    certificate: str


class Client:
    """RASENMAEHER client for one deployment"""

    def __init__(
        self,
        base_url: str | None = None,
        certfile: Path | None = None,
        keyfile: Path | None = None,
        timeout: float | None = None,
    ) -> None:
        self.base_url = (base_url if base_url is not None else config.RMAPI_URL).rstrip("/")
        if not self.base_url:
            raise ValueError("RMSCEP_RMAPI_URL is not set")
        certfile = certfile if certfile is not None else config.CERT
        keyfile = keyfile if keyfile is not None else config.KEY
        # No client certificate is not an error: in a meshed deployment the mesh presents our
        # identity for us and there is nothing here to load.
        self.cert: tuple[str, str] | None = None
        if certfile and keyfile:
            self.cert = (str(certfile), str(keyfile))
        self.timeout = timeout if timeout is not None else config.RMAPI_TIMEOUT

    def _client(self) -> httpx.AsyncClient:
        # The system trust store, because in compose we reach RASENMAEHER through the public mTLS
        # host and that serves a publicly issued certificate. Verifying against the deployment CA
        # here -- which is what devices trust, a different question entirely -- refuses every
        # connection before a single enrolment can be completed.
        verify: str | bool = True
        if config.RMAPI_CA and config.RMAPI_CA.is_file():
            verify = str(config.RMAPI_CA)
        return httpx.AsyncClient(timeout=self.timeout, cert=self.cert, verify=verify)

    async def complete_enrollment(
        self,
        callsign: str,
        csrpem: str,
        request_id: str | None = None,
        forwarded_for: str | None = None,
    ) -> IssuedCertificate:
        """Complete the enrolment an admin planned for this callsign, with the device's own request

        `request_id` and `forwarded_for` are passed through so RASENMAEHER's audit line can be
        joined to ours, and shows the MDM's address rather than this container's.
        """
        url = f"{self.base_url}/api/v1/enrollment/accept"
        headers: dict[str, str] = {}
        if request_id:
            headers["X-Request-ID"] = request_id
        if forwarded_for:
            headers["X-Forwarded-For"] = forwarded_for

        try:
            async with self._client() as client:
                response = await client.post(url, json={"callsign": callsign, "csr": csrpem}, headers=headers)
        except httpx.HTTPError as exc:
            LOGGER.warning("Could not reach RASENMAEHER: %s", exc)
            raise RmapiUnavailable(str(exc)) from exc

        if response.status_code >= 500:
            LOGGER.warning("RASENMAEHER answered %s", response.status_code)
            raise RmapiUnavailable(f"HTTP {response.status_code}")
        if response.status_code != 200:
            # 401/403 is the ordinary answer for a callsign nobody planned, and for us not being
            # a recognised agent. Deliberately one shape either way.
            LOGGER.warning("RASENMAEHER refused %s: HTTP %s", callsign, response.status_code)
            raise RmapiRefused(f"HTTP {response.status_code}")

        try:
            payload = response.json()
        except ValueError as exc:
            raise RmapiUnavailable("answer was not JSON") from exc
        certificate = payload.get("certificate")
        if not certificate:
            # Success without a certificate means the enrolment was accepted down some other path;
            # there is nothing to give the device and it must not be left waiting.
            raise RmapiRefused("no certificate in the answer")
        return IssuedCertificate(callsign=callsign, certificate=str(certificate))
