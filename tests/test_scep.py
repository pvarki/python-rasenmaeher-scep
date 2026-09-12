"""SCEP protocol tests

These build certificate requests the way a device would and feed them through the responder's
parser. No network, no MDM, no phone.
"""

import datetime
import hashlib
import secrets
from pathlib import Path
from typing import Any

import pytest
from asn1crypto import cms
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from cryptography.hazmat.primitives.serialization import pkcs7
from cryptography.x509.oid import NameOID

from rmscep.scep import (
    MSG_PKCS_REQ,
    OID_CHALLENGE_PASSWORD,
    RaIdentity,
    ScepError,
    ca_cert_response,
    cert_rep,
    failure_rep,
    parse_pkcs_req,
    x509_asn1,
)

CHALLENGE = "a-challenge-that-is-not-a-secret"


@pytest.fixture(scope="session")
def ra_identity(tmp_path_factory: pytest.TempPathFactory) -> RaIdentity:
    """The responder's RA identity, generated once because 3072 bit RSA is not free"""
    return RaIdentity.load_or_create(tmp_path_factory.mktemp("ra"))


def _self_signed(key: Any, common_name: str) -> x509.Certificate:
    """What a SCEP client sends along so we have something to encrypt the answer to"""
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])
    now = datetime.datetime.now(datetime.UTC)
    return (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(minutes=5))
        .not_valid_after(now + datetime.timedelta(days=1))
        .sign(key, hashes.SHA256())
    )


def _sign(key: Any, data: bytes) -> bytes:
    """Sign the way the key type requires"""
    if isinstance(key, ec.EllipticCurvePrivateKey):
        return bytes(key.sign(data, ec.ECDSA(hashes.SHA256())))
    signature: bytes = key.sign(data, padding.PKCS1v15(), hashes.SHA256())
    return signature


def _indefinite_length(der: bytes) -> bytes:
    """Re-encode the outer SEQUENCE with an indefinite length, which is legal BER and not DER

    This is what BouncyCastle based SCEP clients emit, and it is what cryptography's strict DER
    parser refuses.
    """
    assert der[0] == 0x30, "expected a SEQUENCE"
    if der[1] & 0x80:
        content = der[2 + (der[1] & 0x7F) :]
    else:
        content = der[2:]
    return bytes([der[0], 0x80]) + content + b"\x00\x00"


def build_pkcs_req(
    ra: RaIdentity,
    callsign: str,
    challenge: str | None = CHALLENGE,
    transaction_id: str = "transaction-1",
    sender_nonce: bytes = b"0123456789abcdef",
    device_key: Any = None,
    force_ber: bool = False,
    sign_with_other_key: bool = False,
) -> bytes:
    """Assemble a PKCSReq exactly as a client would

    force_ber re-encodes the envelope with indefinite length constructed encoding, which is what
    BouncyCastle based clients (jscep, and so the Fleet Android agent) actually send.
    """
    key = device_key or rsa.generate_private_key(public_exponent=65537, key_size=2048)
    builder = x509.CertificateSigningRequestBuilder().subject_name(
        x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, callsign)])
    )
    if challenge is not None:
        builder = builder.add_attribute(x509.ObjectIdentifier(OID_CHALLENGE_PASSWORD), challenge.encode("utf-8"))
    csr = builder.sign(key, hashes.SHA256())

    envelope = (
        pkcs7.PKCS7EnvelopeBuilder()
        .set_data(csr.public_bytes(serialization.Encoding.DER))
        .add_recipient(ra.cert)
        .encrypt(serialization.Encoding.DER, [pkcs7.PKCS7Options.Binary])
    )
    if force_ber:
        envelope = _indefinite_length(envelope)

    device_cert = _self_signed(key, callsign)
    attrs = cms.CMSAttributes(
        [
            cms.CMSAttribute({"type": "content_type", "values": ["data"]}),
            cms.CMSAttribute(
                {
                    "type": "message_digest",
                    "values": [hashlib.sha256(envelope).digest()],
                }
            ),
            cms.CMSAttribute({"type": "scep_message_type", "values": [MSG_PKCS_REQ]}),
            cms.CMSAttribute({"type": "scep_transaction_id", "values": [transaction_id]}),
            cms.CMSAttribute({"type": "scep_sender_nonce", "values": [sender_nonce]}),
        ]
    )
    signing_key = rsa.generate_private_key(public_exponent=65537, key_size=2048) if sign_with_other_key else key
    signature = _sign(signing_key, attrs.dump())
    is_ec = isinstance(signing_key, ec.EllipticCurvePrivateKey)
    signer = cms.SignerInfo(
        {
            "version": "v1",
            "sid": cms.SignerIdentifier(
                "issuer_and_serial_number",
                cms.IssuerAndSerialNumber(
                    {"issuer": x509_asn1(device_cert).issuer, "serial_number": device_cert.serial_number}
                ),
            ),
            "digest_algorithm": {"algorithm": "sha256"},
            "signed_attrs": attrs,
            "signature_algorithm": {"algorithm": "sha256_ecdsa" if is_ec else "rsassa_pkcs1v15"},
            "signature": signature,
        }
    )
    signed = cms.SignedData(
        {
            "version": "v1",
            "digest_algorithms": [{"algorithm": "sha256"}],
            "encap_content_info": {"content_type": "data", "content": envelope},
            "certificates": [cms.CertificateChoices("certificate", x509_asn1(device_cert))],
            "signer_infos": [signer],
        }
    )
    dumped: bytes = cms.ContentInfo({"content_type": "signed_data", "content": signed}).dump()
    return dumped


def test_round_trip(ra_identity: RaIdentity) -> None:
    """The ordinary case: we get the callsign, the challenge and the request back out"""
    body = build_pkcs_req(ra_identity, "OTTER1")
    parsed = parse_pkcs_req(body, ra_identity)
    assert parsed.common_name == "OTTER1"
    assert parsed.challenge == CHALLENGE
    assert parsed.transaction_id == "transaction-1"
    assert "CERTIFICATE REQUEST" in parsed.csr_pem
    request = x509.load_pem_x509_csr(parsed.csr_pem.encode("utf-8"))
    assert request.is_signature_valid


def test_elliptic_curve_device_key(ra_identity: RaIdentity) -> None:
    """A device whose own key is a curve is fine

    Only the RA key has to be RSA, because the envelope is RSA key transport. What the device puts
    in the request is its own business, and a curve is the better choice wherever the MDM offers
    one, so the responder has to verify an ECDSA signed request.
    """
    body = build_pkcs_req(ra_identity, "OTTER2", device_key=ec.generate_private_key(ec.SECP256R1()))
    parsed = parse_pkcs_req(body, ra_identity)
    assert parsed.common_name == "OTTER2"
    request = x509.load_pem_x509_csr(parsed.csr_pem.encode("utf-8"))
    assert isinstance(request.public_key(), ec.EllipticCurvePublicKey)


def test_ber_encoded_envelope(ra_identity: RaIdentity) -> None:
    """BouncyCastle clients send BER, and cryptography's decrypter is strict DER

    This is the bug that cost a day on real hardware: without the re-encode the request fails with
    "error parsing asn1 value: ParseError { kind: InvalidLength }" and the phone just never gets a
    certificate.
    """
    body = build_pkcs_req(ra_identity, "OTTER3", force_ber=True)
    parsed = parse_pkcs_req(body, ra_identity)
    assert parsed.common_name == "OTTER3"


def test_no_challenge_is_reported_as_none(ra_identity: RaIdentity) -> None:
    """A request without the attribute parses; refusing it is the caller's decision"""
    parsed = parse_pkcs_req(build_pkcs_req(ra_identity, "OTTER4", challenge=None), ra_identity)
    assert parsed.challenge is None


def test_forged_signature_is_refused(ra_identity: RaIdentity) -> None:
    """The transaction id and nonces are only worth echoing if the sender really signed them"""
    body = build_pkcs_req(ra_identity, "OTTER5", sign_with_other_key=True)
    with pytest.raises(ScepError):
        parse_pkcs_req(body, ra_identity)


def test_garbage_is_refused(ra_identity: RaIdentity) -> None:
    """Not everything that reaches a public endpoint is a SCEP request"""
    with pytest.raises(ScepError):
        parse_pkcs_req(b"this is not ASN.1 at all", ra_identity)


def test_oversized_request_is_refused_before_any_crypto(ra_identity: RaIdentity) -> None:
    """A private key operation per megabyte of nonsense is not a service we offer"""
    with pytest.raises(ScepError):
        parse_pkcs_req(secrets.token_bytes(70 * 1024), ra_identity)


def test_responses_are_well_formed(ra_identity: RaIdentity) -> None:
    """Success, failure and GetCACert all have to be things a client can parse"""
    body = build_pkcs_req(ra_identity, "OTTER6")
    parsed = parse_pkcs_req(body, ra_identity)

    issued = _self_signed(rsa.generate_private_key(public_exponent=65537, key_size=2048), "OTTER6")
    issued_pem = issued.public_bytes(serialization.Encoding.PEM).decode("utf-8")
    success = cms.ContentInfo.load(cert_rep(ra_identity, parsed, issued_pem))
    assert success["content_type"].native == "signed_data"

    failure = cms.ContentInfo.load(failure_rep(ra_identity, parsed.transaction_id, parsed.sender_nonce, "1"))
    attrs = {attr["type"].native: attr["values"] for attr in failure["content"]["signer_infos"][0]["signed_attrs"]}
    assert attrs["scep_pki_status"][0].native == "2"
    assert attrs["scep_fail_info"][0].native == "1"
    assert attrs["scep_recipient_nonce"][0].native == parsed.sender_nonce

    cacert = cms.ContentInfo.load(ca_cert_response(ra_identity, [issued_pem.encode("utf-8")]))
    assert len(cacert["content"]["certificates"]) == 2


def test_ra_identity_is_stable_and_rsa(tmp_path: Path) -> None:
    """Loading twice must give the same key, or devices encrypt to something we cannot read"""
    first = RaIdentity.load_or_create(tmp_path)
    second = RaIdentity.load_or_create(tmp_path)
    assert first.cert.serial_number == second.cert.serial_number
    assert isinstance(second.key, rsa.RSAPrivateKey)
    assert (tmp_path / "ra.key").stat().st_mode & 0o077 == 0


def test_challenge_attribute_oid_is_the_standard_one() -> None:
    """Cheap guard against a typo nobody would notice until a device silently failed"""
    assert OID_CHALLENGE_PASSWORD == "1.2.840.113549.1.9.7"
