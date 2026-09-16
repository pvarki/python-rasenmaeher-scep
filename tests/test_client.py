"""The SCEP client, driven against the real responder

This is the one test that exercises both halves of the protocol with independent code: the client
builds a request the parser has never seen, and reads a response the responder built. Everything
else stubs one side or the other.

RASENMAEHER is stubbed, but faithfully: it signs the key the CSR actually carries, because "the
issued certificate certifies the device's own key" is the property the whole design exists to
give and the one worth failing a build over.
"""

import datetime
from collections.abc import Generator
from pathlib import Path
from typing import Any

import httpx
import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
from fastapi.testclient import TestClient

from rmscep import client, config
from rmscep.rmapi import IssuedCertificate, RmapiRefused
from rmscep.scep import ScepError
from rmscep.web import scep_views
from rmscep.web.application import get_app_no_init

from .test_scep import CHALLENGE

CALLSIGN = "OTTER21"
CODE = "7F3A9C2B"
URL = "https://responder.test/scep"


def _ca_key_and_name() -> tuple[rsa.RSAPrivateKey, x509.Name]:
    return (
        rsa.generate_private_key(public_exponent=65537, key_size=2048),
        x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Test deployment CA")]),
    )


class _SigningRmapi:
    """Stands in for RASENMAEHER, signing the public key the request actually carried"""

    refuse: Exception | None = None

    def __init__(self) -> None:
        pass

    async def complete_enrollment(self, callsign: str, csrpem: str, **kwargs: Any) -> IssuedCertificate:
        _ = kwargs
        if _SigningRmapi.refuse is not None:
            raise _SigningRmapi.refuse
        csr = x509.load_pem_x509_csr(csrpem.encode("utf-8"))
        ca_key, ca_name = _ca_key_and_name()
        now = datetime.datetime.now(datetime.UTC)
        issued = (
            x509.CertificateBuilder()
            .subject_name(csr.subject)
            .issuer_name(ca_name)
            .public_key(csr.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now)
            .not_valid_after(now + datetime.timedelta(days=30))
            .sign(ca_key, hashes.SHA256())
        )
        return IssuedCertificate(
            callsign=callsign,
            certificate=issued.public_bytes(serialization.Encoding.PEM).decode("utf-8"),
        )


@pytest.fixture
def responder(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Generator[TestClient, None, None]:
    """The real app, with client.py's HTTP calls routed into it instead of the network"""
    ca_key, ca_name = _ca_key_and_name()
    now = datetime.datetime.now(datetime.UTC)
    ca_cert = (
        x509.CertificateBuilder()
        .subject_name(ca_name)
        .issuer_name(ca_name)
        .public_key(ca_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + datetime.timedelta(days=365))
        .sign(ca_key, hashes.SHA256())
    )
    chain = tmp_path / "ca_chain.pem"
    chain.write_bytes(ca_cert.public_bytes(serialization.Encoding.PEM))
    monkeypatch.setattr(config, "DATA_DIR", tmp_path)
    monkeypatch.setattr(config, "CA_CHAIN_PATH", chain)
    monkeypatch.setattr(config, "CHALLENGE", CHALLENGE)
    monkeypatch.setattr(config, "RMAPI_URL", "https://rasenmaeher.test")
    monkeypatch.setattr(scep_views, "Client", _SigningRmapi)
    _SigningRmapi.refuse = None

    with TestClient(get_app_no_init()) as instance:

        def _get(url: str, **kwargs: Any) -> httpx.Response:
            _ = url
            return instance.get("/scep", params=kwargs.get("params"))

        def _post(url: str, **kwargs: Any) -> httpx.Response:
            _ = url
            return instance.post("/scep", params=kwargs.get("params"), content=kwargs.get("content"))

        monkeypatch.setattr(client.httpx, "get", _get)
        monkeypatch.setattr(client.httpx, "post", _post)
        yield instance


def test_capabilities_are_readable(responder: TestClient) -> None:
    """The first thing an operator checks, and the cheapest proof the URL is ours"""
    _ = responder
    caps = client.fetch_capabilities(URL)
    assert "SHA-256" in caps
    assert "POSTPKIOperation" in caps


def test_the_ra_is_picked_by_what_it_is_for_not_by_position(responder: TestClient) -> None:
    """DER sorts the SET OF the certificates travel in, so position means nothing

    Guessing gets you the CA, and encrypting to that produces a malformed-request refusal that
    looks nothing like the trust problem it is.
    """
    _ = responder
    certificates = client.fetch_ra_certificate(URL)
    assert len(certificates) == 2
    assert "rmscep" in client.pick_ra(certificates).subject.rfc4514_string()


def test_picking_the_ra_falls_back_rather_than_failing(responder: TestClient) -> None:
    """A responder publishing no key usage at all should still be talkable to"""
    _ = responder
    without_key_usage = [c for c in client.fetch_ra_certificate(URL) if not c.extensions]
    assert without_key_usage, "the fixture is meant to include a certificate with no extensions"
    assert client.pick_ra(without_key_usage) is without_key_usage[0]


def test_enrolment_certifies_the_key_the_client_generated(responder: TestClient) -> None:
    """The property the whole design exists to give: the private key never left"""
    _ = responder
    enrolled = client.enrol(URL, CALLSIGN, CHALLENGE, proof=f"{CALLSIGN}@{CODE}")
    assert f"CN={CALLSIGN}" in enrolled.subject
    assert CODE in enrolled.subject, "the proof the MDM assigned the callsign should survive into the certificate"


def test_a_refusal_says_why(responder: TestClient) -> None:
    """A CertRep refusal is final, so the reason has to reach the operator rather than a retry"""
    _ = responder
    _SigningRmapi.refuse = RmapiRefused("nobody planned that callsign")
    with pytest.raises(ScepError) as refused:
        client.enrol(URL, "NOBODY1", CHALLENGE)
    assert "failInfo" in str(refused.value)


def test_a_wrong_challenge_is_refused(responder: TestClient) -> None:
    """The challenge is a nuisance filter, and the client should report it as one"""
    _ = responder
    with pytest.raises(ScepError):
        client.enrol(URL, CALLSIGN, "not the configured challenge")


def test_the_proof_goes_somewhere_other_than_the_common_name() -> None:
    """RASENMAEHER reads it from any attribute but the common name, so it must not land there"""
    subject = client.build_subject(CALLSIGN, f"{CALLSIGN}@{CODE}")
    common_names = subject.get_attributes_for_oid(NameOID.COMMON_NAME)
    assert [attribute.value for attribute in common_names] == [CALLSIGN]
    others = [attribute.value for attribute in subject if attribute.oid != NameOID.COMMON_NAME]
    assert others == [f"{CALLSIGN}@{CODE}"]


def test_a_subject_without_a_code_carries_only_the_callsign() -> None:
    """Planned enrolments made before codes were required still have to be expressible"""
    subject = client.build_subject(CALLSIGN, None)
    assert len(list(subject)) == 1
