"""The CLI

Three of these run in a container entrypoint or an init container, so they have to behave when the
happy path does not happen.
"""

import datetime
from pathlib import Path

import httpx
import pytest
from click.testing import CliRunner
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.x509.oid import NameOID

from rmscep import config
from rmscep.console import cli_group


def _signed(csrpem: str) -> str:
    """A certificate for the request, with CFSSL's escaped newlines as the signer really returns"""
    csr = x509.load_pem_x509_csr(csrpem.encode("utf-8"))
    ca_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Test CA")])
    now = datetime.datetime.now(datetime.UTC)
    cert = (
        x509.CertificateBuilder()
        .subject_name(csr.subject)
        .issuer_name(issuer)
        .public_key(csr.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + datetime.timedelta(days=30))
        .sign(ca_key, hashes.SHA256())
    )
    return cert.public_bytes(serialization.Encoding.PEM).decode("utf-8").replace("\n", "\\n")


def test_init_ra_is_idempotent(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """The entrypoint runs this on every start"""
    monkeypatch.setattr(config, "DATA_DIR", tmp_path)
    runner = CliRunner()
    first = runner.invoke(cli_group, ["init-ra"])
    assert first.exit_code == 0
    second = runner.invoke(cli_group, ["init-ra"])
    assert second.exit_code == 0
    # The serial, not the whole output: creating one logs a line that loading one does not.
    serials = [output.rsplit("serial ", 1)[1].strip() for output in (first.output, second.output)]
    assert serials[0] == serials[1], "a restart must not mint a new RA key"
    assert (tmp_path / "ra" / "ra.key").stat().st_mode & 0o077 == 0


def test_client_csr_makes_a_curve_key(tmp_path: Path) -> None:
    """Nothing on this path needs RSA and both cfssl and cert-manager sign ECDSA"""
    keyfile, csrfile = tmp_path / "k.pem", tmp_path / "c.csr"
    result = CliRunner().invoke(
        cli_group,
        ["client-csr", "--common-name", "rmscep", "--keyfile", str(keyfile), "--csrfile", str(csrfile)],
    )
    assert result.exit_code == 0
    key = serialization.load_pem_private_key(keyfile.read_bytes(), password=None)
    assert isinstance(key, ec.EllipticCurvePrivateKey)
    csr = x509.load_pem_x509_csr(csrfile.read_bytes())
    assert [attribute.value for attribute in csr.subject] == ["rmscep"]
    assert csr.is_signature_valid
    assert keyfile.stat().st_mode & 0o077 == 0


def test_client_csr_needs_somewhere_to_write(monkeypatch: pytest.MonkeyPatch) -> None:
    """Rather than silently putting a private key somewhere surprising"""
    monkeypatch.setattr(config, "KEY", None)
    assert CliRunner().invoke(cli_group, ["client-csr"]).exit_code == 1


def test_obtain_cert(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """The init container's whole job"""
    keyfile, certfile = tmp_path / "k.pem", tmp_path / "c.pem"

    def handler(request: httpx.Request) -> httpx.Response:
        payload = request.read().decode("utf-8")
        assert "CERTIFICATE REQUEST" in payload
        import json

        csrpem = json.loads(payload)["certificate_request"]
        return httpx.Response(200, json={"result": {"certificate": _signed(csrpem)}})

    transport = httpx.MockTransport(handler)
    monkeypatch.setattr(httpx, "post", lambda url, **kw: httpx.Client(transport=transport).post(url, **kw))

    result = CliRunner().invoke(
        cli_group,
        ["obtain-cert", "--signer-url", "http://signer.test", "--keyfile", str(keyfile), "--certfile", str(certfile)],
    )
    assert result.exit_code == 0, result.output
    issued = x509.load_pem_x509_certificate(certfile.read_bytes())
    assert [attribute.value for attribute in issued.subject] == ["rmscep"]
    # The certificate must be for the key we kept
    key = serialization.load_pem_private_key(keyfile.read_bytes(), password=None)
    encoding, fmt = serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
    assert issued.public_key().public_bytes(encoding, fmt) == key.public_key().public_bytes(encoding, fmt)

    # Restarting the stack must not churn certificates
    again = CliRunner().invoke(
        cli_group,
        ["obtain-cert", "--signer-url", "http://signer.test", "--keyfile", str(keyfile), "--certfile", str(certfile)],
    )
    assert again.exit_code == 0
    assert "nothing to do" in again.output


def test_obtain_cert_when_the_signer_is_unhappy(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Exit non-zero so the init container fails visibly instead of leaving a half identity"""
    transport = httpx.MockTransport(lambda request: httpx.Response(500, text="no"))
    monkeypatch.setattr(httpx, "post", lambda url, **kw: httpx.Client(transport=transport).post(url, **kw))
    result = CliRunner().invoke(
        cli_group,
        [
            "obtain-cert",
            "--signer-url",
            "http://signer.test",
            "--keyfile",
            str(tmp_path / "k.pem"),
            "--certfile",
            str(tmp_path / "c.pem"),
        ],
    )
    assert result.exit_code == 1
    assert not (tmp_path / "k.pem").exists(), "no key left behind for an identity we never got"


def test_healthcheck_cli(monkeypatch: pytest.MonkeyPatch) -> None:
    """What the container healthcheck runs"""
    transport = httpx.MockTransport(lambda request: httpx.Response(200, json={"healthy": True, "extra": "fine"}))
    monkeypatch.setattr(httpx, "get", lambda url, **kw: httpx.Client(transport=transport).get(url, **kw))
    assert CliRunner().invoke(cli_group, ["healthcheck"]).exit_code == 0

    sad = httpx.MockTransport(lambda request: httpx.Response(200, json={"healthy": False, "extra": "broken"}))
    monkeypatch.setattr(httpx, "get", lambda url, **kw: httpx.Client(transport=sad).get(url, **kw))
    assert CliRunner().invoke(cli_group, ["healthcheck"]).exit_code == 1


def test_healthcheck_cli_when_nothing_is_listening(monkeypatch: pytest.MonkeyPatch) -> None:
    """Before the app is up, which is what a startup probe is for"""

    def boom(url: str, **kwargs: object) -> httpx.Response:
        raise httpx.ConnectError("refused")

    monkeypatch.setattr(httpx, "get", boom)
    assert CliRunner().invoke(cli_group, ["healthcheck"]).exit_code == 1


def _signed_for(csrpem: str, days: int) -> str:
    """Like _signed, but the caller says how long it lasts"""
    csr = x509.load_pem_x509_csr(csrpem.encode("utf-8"))
    ca_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Test CA")])
    now = datetime.datetime.now(datetime.UTC)
    cert = (
        x509.CertificateBuilder()
        .subject_name(csr.subject)
        .issuer_name(issuer)
        .public_key(csr.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=days))
        .sign(ca_key, hashes.SHA256())
    )
    return cert.public_bytes(serialization.Encoding.PEM).decode("utf-8").replace("\n", "\\n")


@pytest.mark.parametrize(
    ("days", "should_renew"),
    [(200, False), (5, True), (-1, True)],
)
def test_obtain_cert_renews_when_the_identity_is_running_out(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, days: int, should_renew: bool
) -> None:
    """Nothing renews the identity while the container runs, so the init container has to

    Its signed lifetime is far shorter than the uptime we want, and an expired client certificate
    means every enrolment fails at the TLS handshake.
    """
    keyfile, certfile = tmp_path / "k.pem", tmp_path / "c.pem"
    issued_lifetimes = iter([days, 400])

    def handler(request: httpx.Request) -> httpx.Response:
        import json

        csrpem = json.loads(request.read().decode("utf-8"))["certificate_request"]
        return httpx.Response(200, json={"result": {"certificate": _signed_for(csrpem, next(issued_lifetimes))}})

    transport = httpx.MockTransport(handler)
    monkeypatch.setattr(httpx, "post", lambda url, **kw: httpx.Client(transport=transport).post(url, **kw))

    args = ["obtain-cert", "--signer-url", "http://signer.test", "--keyfile", str(keyfile), "--certfile", str(certfile)]
    first = CliRunner().invoke(cli_group, args)
    assert first.exit_code == 0, first.output
    before = certfile.read_bytes()

    second = CliRunner().invoke(cli_group, args)
    assert second.exit_code == 0, second.output
    if should_renew:
        assert certfile.read_bytes() != before, "a certificate about to expire must be replaced"
        assert "renewing" in second.output or "does not parse" in second.output
    else:
        assert certfile.read_bytes() == before, "a healthy certificate must not be churned"
        assert "nothing to do" in second.output


def _a_self_signed(common_name: str) -> x509.Certificate:
    """Something the selftest output can name"""
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])
    now = datetime.datetime.now(datetime.UTC)
    return (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + datetime.timedelta(days=30))
        .sign(key, hashes.SHA256())
    )


def test_selftest_says_what_came_back(monkeypatch: pytest.MonkeyPatch) -> None:
    """The point of the command is telling an operator a thing rather than an exit code"""
    from rmscep import client
    from rmscep.console import client as console_client

    _ = console_client
    issued = _a_self_signed("OTTER30")
    monkeypatch.setattr(client, "fetch_capabilities", lambda *a, **kw: ["POSTPKIOperation", "SHA-256"])
    monkeypatch.setattr(client, "fetch_ra_certificate", lambda *a, **kw: [issued])
    monkeypatch.setattr(client, "enrol", lambda *a, **kw: client.Enrolled(certificate=issued, chain=()))

    result = CliRunner().invoke(cli_group, ["selftest", "OTTER30", "--url", "https://x/scep", "--challenge", "c"])
    assert result.exit_code == 0, result.output
    assert "SHA-256" in result.output
    assert "OTTER30" in result.output


def test_selftest_reports_a_refusal_rather_than_a_traceback(monkeypatch: pytest.MonkeyPatch) -> None:
    """A refusal is the interesting outcome: it is how an operator learns the callsign is wrong"""
    from rmscep import client
    from rmscep.scep import ScepError

    monkeypatch.setattr(client, "fetch_capabilities", lambda *a, **kw: ["SHA-256"])
    monkeypatch.setattr(client, "fetch_ra_certificate", lambda *a, **kw: [_a_self_signed("rmscep SCEP RA")])
    monkeypatch.setattr(
        client, "enrol", lambda *a, **kw: (_ for _ in ()).throw(ScepError("refused (failInfo 1): not planned"))
    )
    result = CliRunner().invoke(cli_group, ["selftest", "NOBODY1", "--url", "https://x/scep", "--challenge", "c"])
    assert result.exit_code == 1
    assert "failInfo 1" in result.output


def test_selftest_needs_a_url_and_a_challenge(monkeypatch: pytest.MonkeyPatch) -> None:
    """Both have deployment defaults, so the failure has to name the missing one"""
    monkeypatch.setattr(config, "DOMAIN", "")
    monkeypatch.setattr(config, "CHALLENGE", "")
    runner = CliRunner()
    assert "RMSCEP_DOMAIN" in runner.invoke(cli_group, ["selftest", "OTTER31"]).output
    assert "RMSCEP_CHALLENGE" in runner.invoke(cli_group, ["selftest", "OTTER31", "--url", "https://x"]).output
