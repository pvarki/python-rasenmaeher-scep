"""A SCEP client, so the responder can be proven without an MDM

An enrolment that fails through an MDM fails in one of two places, and from the outside they look
the same: either the responder is wrong, or the MDM never asked it anything. The second is the
common one -- a subject template that does not resolve produces no request at all, so our own logs
stay silent and say nothing about why.

This is the other half of that question. It speaks RFC 8894 and knows nothing about any MDM, so a
run that succeeds here says the responder, the challenge and the planned callsign are all good,
and anything still broken is on the MDM's side of the contract.

It is a test client and not a device: the key it makes lives for one run and is thrown away.
"""

import datetime
import hashlib
import logging
import secrets
from dataclasses import dataclass
from typing import Any

import httpx
from asn1crypto import cms
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.serialization import pkcs7
from cryptography.x509.oid import NameOID

from .scep import MSG_PKCS_REQ, STATUS_SUCCESS, ScepError, x509_asn1

LOGGER = logging.getLogger(__name__)

#: PKCS#9 challengePassword, the attribute an MDM's SCEP profile fills in
OID_CHALLENGE_PASSWORD = "1.2.840.113549.1.9.7"

#: RFC 8894 names failInfo values by number. A device sees only the number, so say them in words.
FAIL_INFO = {
    "0": "the CA does not support the algorithm we asked for",
    "1": "the request was refused: wrong challenge, or the callsign is not planned for a device",
    "2": "the request was malformed",
    "3": "the signature did not verify",
    "4": "the request was not authorised",
}


@dataclass(frozen=True)
class Enrolled:
    """What one successful run got back"""

    certificate: x509.Certificate
    chain: tuple[x509.Certificate, ...]

    @property
    def subject(self) -> str:
        return self.certificate.subject.rfc4514_string()


def _degenerate_certificates(body: bytes) -> list[x509.Certificate]:
    """Read the certificates out of a certs-only PKCS#7, which is how SCEP ships them"""
    try:
        info = cms.ContentInfo.load(body)
        choices = info["content"]["certificates"]
    except Exception as exc:  # pylint: disable=broad-except
        raise ScepError(f"the response is not a PKCS#7 certificate bag: {exc}") from exc
    certificates = []
    for choice in choices:
        if choice.name != "certificate":
            continue
        certificates.append(x509.load_der_x509_certificate(choice.chosen.dump()))
    if not certificates:
        raise ScepError("the response carried no certificate")
    return certificates


def pick_ra(certificates: list[x509.Certificate]) -> x509.Certificate:
    """Which of the certificates in a GetCACert bag a request is encrypted to

    Not the first one. PKCS#7 carries them in a SET OF, and DER sorts a SET OF, so the order is
    whatever the encoding happened to produce -- pick by what the certificate is for instead. A
    client that guesses encrypts to the CA, and the responder then cannot decrypt, which surfaces
    as a malformed request and reads nothing like a trust problem.
    """
    for certificate in certificates:
        try:
            usage = certificate.extensions.get_extension_for_class(x509.KeyUsage).value
        except x509.ExtensionNotFound:
            continue
        if usage.key_encipherment:
            return certificate
    return certificates[0]


def fetch_ra_certificate(base_url: str, verify: Any = True, timeout: float = 30.0) -> list[x509.Certificate]:
    """GetCACert: everything the responder offers -- the RA to encrypt to, and the chain to trust

    Use :func:`pick_ra` to say which is which; the order carries no meaning.
    """
    response = httpx.get(base_url, params={"operation": "GetCACert"}, verify=verify, timeout=timeout)
    if response.status_code != 200:
        raise ScepError(f"GetCACert answered HTTP {response.status_code}")
    return _degenerate_certificates(response.content)


def fetch_capabilities(base_url: str, verify: Any = True, timeout: float = 30.0) -> list[str]:
    """GetCACaps: what the responder says it can do"""
    response = httpx.get(base_url, params={"operation": "GetCACaps"}, verify=verify, timeout=timeout)
    if response.status_code != 200:
        raise ScepError(f"GetCACaps answered HTTP {response.status_code}")
    return [line.strip() for line in response.text.splitlines() if line.strip()]


def _self_signed(key: rsa.RSAPrivateKey, subject: x509.Name) -> x509.Certificate:
    """The throwaway identity a PKCSReq is signed with and a CertRep is encrypted to

    SCEP has no identity to sign a first request with, so a client signs with a self-signed
    certificate over the key it is asking us to certify. Nothing trusts it and nothing should.
    """
    now = datetime.datetime.now(datetime.UTC)
    return (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(minutes=5))
        .not_valid_after(now + datetime.timedelta(days=1))
        .sign(key, hashes.SHA256())
    )


def build_subject(callsign: str, proof: str | None) -> x509.Name:
    """CN carries the callsign, one more RDN carries the proof the MDM assigned it

    RASENMAEHER accepts the proof in any attribute that is not the common name, so which one is
    the MDM's choice and not ours. OU is used here because it is the one every MDM's subject
    template can write.
    """
    attributes = [x509.NameAttribute(NameOID.COMMON_NAME, callsign)]
    if proof:
        attributes.append(x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, proof))
    return x509.Name(attributes)


def build_pkcs_req(
    ra_certificate: x509.Certificate,
    key: rsa.RSAPrivateKey,
    subject: x509.Name,
    challenge: str,
    transaction_id: str,
    sender_nonce: bytes,
) -> tuple[bytes, x509.Certificate]:
    """Assemble a PKCSReq: a CSR, encrypted to the RA, signed by the key being certified"""
    csr = (
        x509.CertificateSigningRequestBuilder()
        .subject_name(subject)
        .add_attribute(x509.ObjectIdentifier(OID_CHALLENGE_PASSWORD), challenge.encode("utf-8"))
        .sign(key, hashes.SHA256())
    )
    envelope = (
        pkcs7.PKCS7EnvelopeBuilder()
        .set_data(csr.public_bytes(serialization.Encoding.DER))
        .add_recipient(ra_certificate)
        .encrypt(serialization.Encoding.DER, [pkcs7.PKCS7Options.Binary])
    )

    device_cert = _self_signed(key, subject)
    attrs = cms.CMSAttributes(
        [
            cms.CMSAttribute({"type": "content_type", "values": ["data"]}),
            cms.CMSAttribute({"type": "message_digest", "values": [hashlib.sha256(envelope).digest()]}),
            cms.CMSAttribute({"type": "scep_message_type", "values": [MSG_PKCS_REQ]}),
            cms.CMSAttribute({"type": "scep_transaction_id", "values": [transaction_id]}),
            cms.CMSAttribute({"type": "scep_sender_nonce", "values": [sender_nonce]}),
        ]
    )
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
            "signature_algorithm": {"algorithm": "rsassa_pkcs1v15"},
            # The signature covers the attributes as an explicit SET OF, not the implicit [0] they
            # appear as inside SignerInfo.
            "signature": key.sign(attrs.dump(), padding.PKCS1v15(), hashes.SHA256()),
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
    body: bytes = cms.ContentInfo({"content_type": "signed_data", "content": signed}).dump()
    return body, device_cert


def read_cert_rep(body: bytes, key: rsa.RSAPrivateKey, device_cert: x509.Certificate) -> list[x509.Certificate]:
    """Read a CertRep, raising the responder's own reason when it says no

    A refusal is final by design: the device is meant to stop rather than retry a callsign it was
    never going to get. So the reason is worth reporting rather than swallowing.
    """
    try:
        info = cms.ContentInfo.load(body)
        signed = info["content"]
        attrs = {attr["type"].native: attr["values"] for attr in signed["signer_infos"][0]["signed_attrs"]}
        status = str(attrs["scep_pki_status"][0].native)
    except Exception as exc:  # pylint: disable=broad-except
        raise ScepError(f"the response is not a CertRep: {exc}") from exc

    if status != STATUS_SUCCESS:
        fail_info = str(attrs["scep_fail_info"][0].native) if "scep_fail_info" in attrs else "?"
        raise ScepError(f"refused (failInfo {fail_info}): {FAIL_INFO.get(fail_info, 'no reason given')}")

    enveloped = signed["encap_content_info"]["content"].native
    try:
        inner = pkcs7.pkcs7_decrypt_der(enveloped, device_cert, key, [])
    except Exception as exc:  # pylint: disable=broad-except
        raise ScepError(f"could not decrypt the issued certificate: {exc}") from exc
    return _degenerate_certificates(inner)


def enrol(  # pylint: disable=too-many-arguments,too-many-positional-arguments
    base_url: str,
    callsign: str,
    challenge: str,
    proof: str | None = None,
    verify: Any = True,
    timeout: float = 60.0,
) -> Enrolled:
    """One whole enrolment, the way a device would do it

    The key is generated here and never leaves, which is the property the whole design exists to
    give a device: what comes back certifies a key the responder never saw.
    """
    ra_certificate = pick_ra(fetch_ra_certificate(base_url, verify=verify, timeout=timeout))
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    transaction_id = secrets.token_hex(20)
    body, device_cert = build_pkcs_req(
        ra_certificate,
        key,
        build_subject(callsign, proof),
        challenge,
        transaction_id,
        secrets.token_bytes(16),
    )
    response = httpx.post(
        base_url,
        params={"operation": "PKIOperation"},
        content=body,
        headers={"Content-Type": "application/x-pki-message"},
        verify=verify,
        timeout=timeout,
    )
    if response.status_code != 200:
        # A 503 is the responder saying it could not reach RASENMAEHER, which is transient and
        # deliberately not answered as a signed refusal, because a signed refusal is final.
        raise ScepError(f"PKIOperation answered HTTP {response.status_code}")
    certificates = read_cert_rep(response.content, key, device_cert)
    issued = certificates[0]
    if issued.public_key().public_numbers() != key.public_key().public_numbers():  # type: ignore[union-attr]
        raise ScepError("the issued certificate is for a different key than we asked for")
    return Enrolled(certificate=issued, chain=tuple(certificates[1:]))
