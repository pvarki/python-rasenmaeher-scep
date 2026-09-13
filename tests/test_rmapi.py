"""Talking to RASENMAEHER

One call, and what matters is that each answer is turned into the right thing to tell the device.
A refusal is final; an outage is worth retrying.
"""

from pathlib import Path

import httpx
import pytest

from rmscep import config
from rmscep.rmapi import Client, IssuedCertificate, RmapiRefused, RmapiUnavailable

CERT = "-----BEGIN CERTIFICATE-----\nnot really\n-----END CERTIFICATE-----\n"


def _client(handler: object, monkeypatch: pytest.MonkeyPatch) -> Client:
    """A Client whose transport is ours"""
    instance = Client(base_url="https://rasenmaeher.test")
    transport = httpx.MockTransport(handler)  # type: ignore[arg-type]
    monkeypatch.setattr(instance, "_client", lambda: httpx.AsyncClient(transport=transport))
    return instance


def test_url_is_required(monkeypatch: pytest.MonkeyPatch) -> None:
    """Refusing to start beats pretending to work"""
    monkeypatch.setattr(config, "RMAPI_URL", "")
    with pytest.raises(ValueError):
        Client()


def test_no_client_certificate_is_not_an_error(monkeypatch: pytest.MonkeyPatch) -> None:
    """In the mesh there is no certificate to load: the mesh presents our identity for us"""
    monkeypatch.setattr(config, "CERT", None)
    monkeypatch.setattr(config, "KEY", None)
    assert Client(base_url="https://rasenmaeher.test").cert is None


def test_client_certificate_is_used_when_configured(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    """Outside the mesh we authenticate with our own certificate from the deployment CA"""
    certfile, keyfile = tmp_path / "c.pem", tmp_path / "k.pem"
    certfile.touch()
    keyfile.touch()
    monkeypatch.setattr(config, "CERT", certfile)
    monkeypatch.setattr(config, "KEY", keyfile)
    assert Client(base_url="https://rasenmaeher.test").cert == (str(certfile), str(keyfile))


@pytest.mark.asyncio
async def test_success(monkeypatch: pytest.MonkeyPatch) -> None:
    """The certificate comes back in the answer, so we need no credential to fetch it"""
    seen: dict[str, object] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        seen["url"] = str(request.url)
        seen["request-id"] = request.headers.get("X-Request-ID")
        seen["forwarded"] = request.headers.get("X-Forwarded-For")
        return httpx.Response(200, json={"success": True, "certificate": CERT})

    client = _client(handler, monkeypatch)
    issued = await client.complete_enrollment("OTTER1", "csr", request_id="abc", forwarded_for="10.0.0.1")
    assert issued == IssuedCertificate(callsign="OTTER1", certificate=CERT)
    assert seen["url"] == "https://rasenmaeher.test/api/v1/enrollment/accept"
    # Passed through so the audit line joins ours and shows the MDM, not this container
    assert seen["request-id"] == "abc"
    assert seen["forwarded"] == "10.0.0.1"


@pytest.mark.asyncio
@pytest.mark.parametrize("status", [400, 401, 403, 409])
async def test_refusals_are_final(monkeypatch: pytest.MonkeyPatch, status: int) -> None:
    """Not planned, already taken, not ours to complete: the device gains nothing by asking again"""
    client = _client(lambda request: httpx.Response(status, json={"detail": "no"}), monkeypatch)
    with pytest.raises(RmapiRefused):
        await client.complete_enrollment("OTTER1", "csr")


@pytest.mark.asyncio
async def test_server_errors_are_worth_retrying(monkeypatch: pytest.MonkeyPatch) -> None:
    """Someone else's bad day, not a verdict on this device"""
    client = _client(lambda request: httpx.Response(503, text="nope"), monkeypatch)
    with pytest.raises(RmapiUnavailable):
        await client.complete_enrollment("OTTER1", "csr")


@pytest.mark.asyncio
async def test_unreachable(monkeypatch: pytest.MonkeyPatch) -> None:
    """Nothing answered at all"""

    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("no route", request=request)

    client = _client(handler, monkeypatch)
    with pytest.raises(RmapiUnavailable):
        await client.complete_enrollment("OTTER1", "csr")


@pytest.mark.asyncio
async def test_success_without_a_certificate_is_a_refusal(monkeypatch: pytest.MonkeyPatch) -> None:
    """A 200 with nothing in it leaves the device with nothing, so say so rather than hang"""
    client = _client(lambda request: httpx.Response(200, json={"success": True}), monkeypatch)
    with pytest.raises(RmapiRefused):
        await client.complete_enrollment("OTTER1", "csr")


@pytest.mark.asyncio
async def test_answer_that_is_not_json(monkeypatch: pytest.MonkeyPatch) -> None:
    """Something is in front of RASENMAEHER that should not be"""
    client = _client(lambda request: httpx.Response(200, text="<html>hello</html>"), monkeypatch)
    with pytest.raises(RmapiUnavailable):
        await client.complete_enrollment("OTTER1", "csr")


def _captured_verify(monkeypatch: pytest.MonkeyPatch) -> object:
    """What the client would hand httpx as its trust store"""
    seen: dict[str, object] = {}

    class _Recorder:
        def __init__(self, **kwargs: object) -> None:
            seen.update(kwargs)

    monkeypatch.setattr(httpx, "AsyncClient", _Recorder)
    Client(base_url="https://rasenmaeher.test")._client()
    return seen["verify"]


def test_rmapi_tls_uses_the_system_store(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    """The deployment CA is what devices trust, not what RASENMAEHER is served with

    In compose we reach it through the public mTLS host, whose certificate is publicly issued.
    Pinning to the deployment CA chain here refused every connection, so nothing could enrol.
    """
    ca_chain = tmp_path / "ca_chain.pem"
    ca_chain.write_text("-----BEGIN CERTIFICATE-----\nnope\n-----END CERTIFICATE-----\n", encoding="utf-8")
    monkeypatch.setattr(config, "CA_CHAIN_PATH", ca_chain)
    monkeypatch.setattr(config, "RMAPI_CA", None)
    assert _captured_verify(monkeypatch) is True, "the CA chain must not become the trust store"


def test_rmapi_ca_overrides_when_set(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    """For a deployment that reaches RASENMAEHER on a name the system store does not know"""
    own_ca = tmp_path / "rmapi_ca.pem"
    own_ca.write_text("-----BEGIN CERTIFICATE-----\nnope\n-----END CERTIFICATE-----\n", encoding="utf-8")
    monkeypatch.setattr(config, "RMAPI_CA", own_ca)
    assert _captured_verify(monkeypatch) == str(own_ca)


def test_rmapi_ca_that_does_not_exist_is_ignored(monkeypatch: pytest.MonkeyPatch) -> None:
    """A misconfigured path must not silently disable verification"""
    monkeypatch.setattr(config, "RMAPI_CA", Path("/nonexistent/ca.pem"))
    assert _captured_verify(monkeypatch) is True
