"""The SCEP endpoints, end to end through the app

RASENMAEHER is stubbed: what is under test here is the protocol surface and the decisions the
responder makes before and after it asks.
"""

import datetime
from collections.abc import Generator
from pathlib import Path
from typing import Any

import pytest
from asn1crypto import cms
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
from fastapi.testclient import TestClient

from rmscep import config
from rmscep.rmapi import IssuedCertificate, RmapiRefused, RmapiUnavailable
from rmscep.scep import CAPS
from rmscep.web import scep_views
from rmscep.web.application import get_app_no_init

from .test_scep import CHALLENGE, build_pkcs_req

ISSUED_CALLSIGN = "OTTER9"


def _a_certificate(common_name: str) -> str:
    """Something shaped like what the CA would hand back"""
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])
    now = datetime.datetime.now(datetime.UTC)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + datetime.timedelta(days=1))
        .sign(key, hashes.SHA256())
    )
    return cert.public_bytes(serialization.Encoding.PEM).decode("utf-8")


class _StubRmapi:
    """Stands in for RASENMAEHER"""

    raises: Exception | None = None

    def __init__(self) -> None:
        pass

    async def complete_enrollment(self, callsign: str, csrpem: str, **kwargs: Any) -> IssuedCertificate:
        _ = csrpem, kwargs
        if _StubRmapi.raises is not None:
            raise _StubRmapi.raises
        return IssuedCertificate(callsign=callsign, certificate=_a_certificate(callsign))


@pytest.fixture
def client(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Generator[TestClient, None, None]:
    """An app with its own RA identity, a CA chain on disk and RASENMAEHER stubbed out"""
    ca_chain = tmp_path / "ca_chain.pem"
    ca_chain.write_text(_a_certificate("Test CA"), encoding="utf-8")
    monkeypatch.setattr(config, "DATA_DIR", tmp_path)
    monkeypatch.setattr(config, "CA_CHAIN_PATH", ca_chain)
    monkeypatch.setattr(config, "CHALLENGE", CHALLENGE)
    monkeypatch.setattr(config, "RMAPI_URL", "https://rasenmaeher.test")
    monkeypatch.setattr(scep_views, "Client", _StubRmapi)
    _StubRmapi.raises = None
    with TestClient(get_app_no_init()) as instance:
        yield instance


def _pki_status(body: bytes) -> tuple[str, str | None]:
    """Read the status and failInfo out of a CertRep"""
    info = cms.ContentInfo.load(body)
    attrs = {attr["type"].native: attr["values"] for attr in info["content"]["signer_infos"][0]["signed_attrs"]}
    fail = attrs.get("scep_fail_info")
    return str(attrs["scep_pki_status"][0].native), (str(fail[0].native) if fail else None)


def test_getcacaps(client: TestClient) -> None:
    """What we tell a client we can do"""
    response = client.get("/scep", params={"operation": "GetCACaps"})
    assert response.status_code == 200
    assert response.text == CAPS
    assert "SHA-256" in response.text
    assert "SHA-1" not in response.text


def test_getcacert(client: TestClient) -> None:
    """The RA certificate devices encrypt to, plus the chain they must trust"""
    response = client.get("/scep", params={"operation": "GetCACert"})
    assert response.status_code == 200
    assert response.headers["content-type"].startswith("application/x-x509-ca-ra-cert")
    certs = cms.ContentInfo.load(response.content)["content"]["certificates"]
    assert len(certs) == 2


def test_unknown_operation(client: TestClient) -> None:
    """Not everything that reaches a public endpoint is SCEP"""
    assert client.get("/scep", params={"operation": "Nonsense"}).status_code == 400
    assert client.post("/scep", params={"operation": "Nonsense"}, content=b"x").status_code == 400


def test_enrolment(client: TestClient, tmp_path: Path) -> None:
    """The ordinary case: the device gets a certificate for the key it holds"""
    ra = __import__("rmscep.scep", fromlist=["RaIdentity"]).RaIdentity.load_or_create(tmp_path / "ra")
    body = build_pkcs_req(ra, ISSUED_CALLSIGN)
    response = client.post("/scep", params={"operation": "PKIOperation"}, content=body)
    assert response.status_code == 200
    assert response.headers["content-type"].startswith("application/x-pki-message")
    status, fail = _pki_status(response.content)
    assert (status, fail) == ("0", None)


def test_wrong_challenge_is_refused(client: TestClient, tmp_path: Path) -> None:
    """The challenge is a nuisance filter, but it is still checked"""
    ra = __import__("rmscep.scep", fromlist=["RaIdentity"]).RaIdentity.load_or_create(tmp_path / "ra")
    body = build_pkcs_req(ra, ISSUED_CALLSIGN, challenge="not the one")
    response = client.post("/scep", params={"operation": "PKIOperation"}, content=body)
    assert response.status_code == 200, "a refusal is still a signed CertRep, not an HTTP error"
    assert _pki_status(response.content) == ("2", "1")


def test_no_challenge_configured_refuses_everything(
    client: TestClient, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """An unconfigured responder must not become an open endpoint"""
    monkeypatch.setattr(config, "CHALLENGE", "")
    ra = __import__("rmscep.scep", fromlist=["RaIdentity"]).RaIdentity.load_or_create(tmp_path / "ra")
    body = build_pkcs_req(ra, ISSUED_CALLSIGN)
    response = client.post("/scep", params={"operation": "PKIOperation"}, content=body)
    assert _pki_status(response.content)[0] == "2"


def test_a_refusal_is_final_and_signed(client: TestClient, tmp_path: Path) -> None:
    """Not planned, already taken, not ours: the device gains nothing by asking again"""
    _StubRmapi.raises = RmapiRefused("not planned")
    ra = __import__("rmscep.scep", fromlist=["RaIdentity"]).RaIdentity.load_or_create(tmp_path / "ra")
    body = build_pkcs_req(ra, ISSUED_CALLSIGN)
    response = client.post("/scep", params={"operation": "PKIOperation"}, content=body)
    assert response.status_code == 200, "a refusal is a signed CertRep, not an HTTP error"
    assert _pki_status(response.content) == ("2", "1")


def test_an_outage_is_retryable_not_a_verdict(client: TestClient, tmp_path: Path) -> None:
    """A CertRep carrying failInfo is FINAL to a SCEP client

    Answering one when RASENMAEHER merely hiccuped spends the enrolment for good. The front proxy
    OCSP-checks our client certificate and a freshly issued one is unknown to the responder until
    its next refresh, so this is an ordinary startup condition, not a rare one.
    """
    _StubRmapi.raises = RmapiUnavailable("down")
    ra = __import__("rmscep.scep", fromlist=["RaIdentity"]).RaIdentity.load_or_create(tmp_path / "ra")
    body = build_pkcs_req(ra, ISSUED_CALLSIGN)
    response = client.post("/scep", params={"operation": "PKIOperation"}, content=body)
    assert response.status_code == 503, "the MDM has to be able to come back"
    assert b"BEGIN" not in response.content and response.headers["content-type"].startswith("text/plain")


def test_oversized_body_is_refused_without_parsing(client: TestClient) -> None:
    """A private key operation per megabyte of nonsense is not a service we offer"""
    response = client.post("/scep", params={"operation": "PKIOperation"}, content=b"x" * (70 * 1024))
    assert response.status_code == 413


def test_malformed_body(client: TestClient) -> None:
    """Nothing parsed means no transaction to answer within, so an HTTP error is all we have"""
    response = client.post("/scep", params={"operation": "PKIOperation"}, content=b"not asn.1")
    assert response.status_code == 400


def test_healthcheck_reports_configuration(client: TestClient, monkeypatch: pytest.MonkeyPatch) -> None:
    """Healthy means this service works, not that somebody configured it to do anything"""
    healthy = client.get("/api/v1/healthcheck").json()
    assert healthy["healthy"] is True
    assert "RA serial" in str(healthy["extra"])

    monkeypatch.setattr(config, "CHALLENGE", "")
    idle = client.get("/api/v1/healthcheck").json()
    assert idle["healthy"] is True, "unconfigured is idle, not broken -- autoheal would loop otherwise"
    assert "enrolment refused" in str(idle["extra"])

    monkeypatch.setattr(config, "CA_CHAIN_PATH", Path("/nonexistent/ca_chain.pem"))
    broken = client.get("/api/v1/healthcheck").json()
    assert broken["healthy"] is False


def _client_cert(tmp_path: Path, days: int) -> tuple[Path, Path]:
    """A client identity that expires in `days` days (negative for already expired)"""
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "rmscep")])
    now = datetime.datetime.now(datetime.UTC)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=400))
        .not_valid_after(now + datetime.timedelta(days=days))
        .sign(key, hashes.SHA256())
    )
    certfile, keyfile = tmp_path / "rmscep.pem", tmp_path / "rmscep.key"
    certfile.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    keyfile.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    return certfile, keyfile


def test_healthcheck_looks_at_the_client_identity(
    client: TestClient, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Without a usable client certificate not one enrolment can be completed

    Reporting healthy anyway hides the single thing most likely to take this service off the air,
    because the certificate is short lived and nothing renews it while the container keeps running.
    """
    certfile, keyfile = _client_cert(tmp_path, days=200)
    monkeypatch.setattr(config, "CERT", certfile)
    monkeypatch.setattr(config, "KEY", keyfile)
    good = client.get("/api/v1/healthcheck").json()
    assert good["healthy"] is True
    assert "client certificate valid" in str(good["extra"])

    monkeypatch.setattr(config, "CERT", tmp_path / "gone.pem")
    missing = client.get("/api/v1/healthcheck").json()
    assert missing["healthy"] is False, "a missing identity is not healthy"

    old_dir = tmp_path / "old"
    old_dir.mkdir()
    expired_cert, expired_key = _client_cert(old_dir, days=-1)
    monkeypatch.setattr(config, "CERT", expired_cert)
    monkeypatch.setattr(config, "KEY", expired_key)
    expired = client.get("/api/v1/healthcheck").json()
    assert expired["healthy"] is False, "an expired identity is not healthy"
    assert "expired" in str(expired["extra"])


def test_healthcheck_in_the_mesh_needs_no_certificate(client: TestClient, monkeypatch: pytest.MonkeyPatch) -> None:
    """Where the mesh presents our identity there is nothing on disk to check"""
    monkeypatch.setattr(config, "CERT", None)
    monkeypatch.setattr(config, "KEY", None)
    meshed = client.get("/api/v1/healthcheck").json()
    assert meshed["healthy"] is True
    assert "from the mesh" in str(meshed["extra"])
