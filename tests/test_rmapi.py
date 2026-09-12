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
