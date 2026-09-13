"""The SCEP endpoints

Three operations, and only one of them does anything interesting. Every refusal is answered as a
signed CertRep carrying a failInfo rather than an HTTP error, because that is what makes the MDM
stop and report a failed certificate instead of retrying for ever.
"""

import logging

from fastapi import APIRouter, Request, Response

from .. import config
from ..rmapi import Client, RmapiRefused, RmapiUnavailable
from ..scep import (
    CAPS,
    FAIL_BAD_IDENTITY,
    FAIL_BAD_REQUEST,
    MAX_REQUEST_BYTES,
    ScepError,
    ca_cert_response,
    cert_rep,
    failure_rep,
    parse_pkcs_req,
)
from .deps import get_ra

LOGGER = logging.getLogger(__name__)
router = APIRouter()

PKI_MESSAGE = "application/x-pki-message"
CA_RA_CERT = "application/x-x509-ca-ra-cert"


def _safe(value: str, limit: int = 64) -> str:
    """Bounded, printable version of something a device sent us, for the log"""
    cleaned = "".join(char for char in value if char.isprintable())
    return cleaned[:limit]


@router.get("")
@router.get("/")
async def scep_get(request: Request, operation: str = "") -> Response:
    """GetCACaps and GetCACert"""
    if operation == "GetCACaps":
        return Response(content=CAPS.encode("utf-8"), media_type="text/plain")
    if operation == "GetCACert":
        ca_pems = []
        if config.CA_CHAIN_PATH.is_file():
            ca_pems.append(config.CA_CHAIN_PATH.read_bytes())
        else:
            # Devices would be handed a certificate they cannot build a chain for.
            LOGGER.error("CA chain %s is missing, answering with the RA certificate alone", config.CA_CHAIN_PATH)
        return Response(content=ca_cert_response(get_ra(request), ca_pems), media_type=CA_RA_CERT)
    return Response(content=b"unsupported operation", status_code=400, media_type="text/plain")


@router.post("")
@router.post("/")
async def scep_post(request: Request, operation: str = "") -> Response:
    """PKIOperation: the device asks for a certificate"""
    if operation != "PKIOperation":
        return Response(content=b"unsupported operation", status_code=400, media_type="text/plain")

    body = await request.body()
    if len(body) > MAX_REQUEST_BYTES:
        LOGGER.warning("Refusing a %s byte request", len(body))
        return Response(content=b"request too large", status_code=413, media_type="text/plain")

    ra = get_ra(request)
    try:
        parsed = parse_pkcs_req(body, ra)
    except ScepError as exc:
        # Nothing parsed, so there is no transaction id to answer within: an HTTP error is all we
        # can honestly give.
        LOGGER.warning("Refusing a malformed request: %s", exc)
        return Response(content=b"bad request", status_code=400, media_type="text/plain")

    transaction = _safe(parsed.transaction_id)
    callsign = parsed.common_name

    def refuse(reason: str, fail_info: str) -> Response:
        LOGGER.warning(
            "Refusing %s: %s [transaction=%s]",
            _safe(callsign),
            reason,
            transaction,
        )
        return Response(
            content=failure_rep(ra, parsed.transaction_id, parsed.sender_nonce, fail_info),
            media_type=PKI_MESSAGE,
        )

    if not config.CHALLENGE:
        # Refusing to run without one is deliberate: an empty setting would otherwise mean an
        # endpoint that accepts anything, which is the opposite of what it is for.
        return refuse("no challenge is configured", FAIL_BAD_REQUEST)
    if parsed.challenge != config.CHALLENGE:
        return refuse("wrong challenge", FAIL_BAD_IDENTITY)

    try:
        issued = await Client().complete_enrollment(
            callsign=callsign,
            csrpem=parsed.csr_pem,
            request_id=request.headers.get("X-Request-ID"),
            forwarded_for=request.headers.get("X-Forwarded-For") or request.headers.get("X-Real-IP"),
        )
    except RmapiRefused as exc:
        # Not planned, already taken, or not ours to complete. The device cannot fix this by
        # retrying; the operator plans another callsign.
        return refuse(f"rasenmaeher refused ({exc})", FAIL_BAD_IDENTITY)
    except RmapiUnavailable as exc:
        # Somebody else's bad day, not a verdict on this device, so it must NOT get a signed
        # failure: a CertRep carrying failInfo is final to a SCEP client and would spend the
        # enrolment on a hiccup. An HTTP error is the one answer the MDM will come back from.
        # Reachable in ordinary operation: the front proxy OCSP-checks our client certificate and
        # a freshly issued one is unknown to the responder until its next refresh.
        LOGGER.warning(
            "Answering 503 for %s, rasenmaeher unavailable (%s) [transaction=%s]",
            _safe(callsign),
            exc,
            transaction,
        )
        return Response(content=b"rasenmaeher unavailable", status_code=503, media_type="text/plain")

    LOGGER.info("Issued a certificate to %s [transaction=%s]", _safe(callsign), transaction)
    return Response(content=cert_rep(ra, parsed, issued.certificate), media_type=PKI_MESSAGE)
