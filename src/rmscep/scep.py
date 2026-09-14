"""SCEP protocol, RFC 8894

Ported from the proof of concept that ran this against real hardware. What the responder does is
deliberately small: it unwraps the device's certificate request and hands it to RASENMAEHER, which
is the certificate authority. Nothing is signed here.

Why SCEP at all: the device has to generate its own private key, and with no application of ours on
the phone the only thing that can make it do so is the platform, driven by the MDM. SCEP is the one
protocol every MDM speaks for that.

`cryptography` cannot attach SCEP's custom signed attributes (messageType, transactionID, the
nonces), so the CMS is assembled with asn1crypto and signed with cryptography.
"""

from __future__ import annotations

import datetime
import hashlib
import logging
import secrets
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from asn1crypto import cms, core
from asn1crypto import x509 as a_x509
from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, padding, rsa
from cryptography.hazmat.primitives.serialization import pkcs7
from cryptography.x509.oid import NameOID

LOGGER = logging.getLogger(__name__)

# SCEP attribute OIDs (draft-nourse-scep, kept by RFC 8894). PrintableString except the nonces.
OID_MESSAGE_TYPE = "2.16.840.1.113733.1.9.2"
OID_PKI_STATUS = "2.16.840.1.113733.1.9.3"
OID_FAIL_INFO = "2.16.840.1.113733.1.9.4"
OID_SENDER_NONCE = "2.16.840.1.113733.1.9.5"
OID_RECIPIENT_NONCE = "2.16.840.1.113733.1.9.6"
OID_TRANSACTION_ID = "2.16.840.1.113733.1.9.7"
OID_CHALLENGE_PASSWORD = "1.2.840.113549.1.9.7"  # nosec B105 -- an object identifier, not a credential

MSG_CERT_REP = "3"
MSG_PKCS_REQ = "19"
STATUS_SUCCESS = "0"
STATUS_FAILURE = "2"
FAIL_BAD_REQUEST = "2"
FAIL_BAD_IDENTITY = "1"

# What we tell clients we can do. POSTPKIOperation keeps the request out of the query string,
# SHA-256 and AES keep them off MD5 and DES, which is what a client falls back to when nothing
# better is advertised. SCEPStandard means RFC 8894 rather than the older draft.
CAPS = "POSTPKIOperation\nSHA-256\nAES\nSCEPStandard\n"

# A PKCSReq is a few kilobytes. Anything larger is not a device we want to spend a private key
# operation on.
MAX_REQUEST_BYTES = 64 * 1024


class _SetOfPrintableString(core.SetOf):  # type: ignore[misc]
    _child_spec = core.PrintableString


class _SetOfOctetString(core.SetOf):  # type: ignore[misc]
    _child_spec = core.OctetString


def _register_scep_attributes() -> None:
    """Teach asn1crypto the SCEP attribute types. Idempotent."""
    mapping = {
        OID_MESSAGE_TYPE: ("scep_message_type", _SetOfPrintableString),
        OID_PKI_STATUS: ("scep_pki_status", _SetOfPrintableString),
        OID_FAIL_INFO: ("scep_fail_info", _SetOfPrintableString),
        OID_SENDER_NONCE: ("scep_sender_nonce", _SetOfOctetString),
        OID_RECIPIENT_NONCE: ("scep_recipient_nonce", _SetOfOctetString),
        OID_TRANSACTION_ID: ("scep_transaction_id", _SetOfPrintableString),
    }
    for oid, (name, spec) in mapping.items():
        cms.CMSAttributeType._map[oid] = name
        cms.CMSAttribute._oid_specs[name] = spec


_register_scep_attributes()


class ScepError(Exception):
    """A request we are refusing, carrying the SCEP failInfo code to answer with"""

    def __init__(self, message: str, fail_info: str = FAIL_BAD_REQUEST) -> None:
        super().__init__(message)
        self.fail_info = fail_info


@dataclass
class RaIdentity:
    """The responder's own key pair. Devices encrypt their certificate request to this certificate.

    RSA, and not by preference: SCEP wraps the request in a CMS EnvelopedData whose content
    encryption key is transported with the recipient's public key, and key transport is an RSA
    operation. Elliptic curve keys can only do key agreement there, which SCEP does not define and
    no MDM client implements -- `cryptography` says so outright, refusing an EC recipient with
    "Only RSA keys are supported at this time". So this one key stays RSA while everything else we
    generate is a curve.

    Self-signed and separate from any other identity we hold on purpose: this key exists to decrypt
    envelopes, and a certificate issued for client authentication may not even permit that.
    """

    key: rsa.RSAPrivateKey
    cert: x509.Certificate

    @classmethod
    def load_or_create(cls, directory: Path) -> RaIdentity:
        """Load the RA identity, generating it on first run

        Call this once before any web worker starts. Several workers racing on an empty directory
        would each generate a key and the last writer would win, leaving most requests unable to
        decrypt anything.
        """
        directory.mkdir(parents=True, exist_ok=True)
        keyfile, certfile = directory / "ra.key", directory / "ra.crt"
        if keyfile.is_file() and certfile.is_file():
            loaded = serialization.load_pem_private_key(keyfile.read_bytes(), password=None)
            if not isinstance(loaded, rsa.RSAPrivateKey):
                raise ValueError(f"{keyfile} is not an RSA key, see the class docstring for why it must be")
            return cls(key=loaded, cert=x509.load_pem_x509_certificate(certfile.read_bytes()))

        LOGGER.info("Generating the SCEP RA identity into %s", directory)
        key = rsa.generate_private_key(public_exponent=65537, key_size=3072)
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "rmscep SCEP RA")])
        now = datetime.datetime.now(datetime.UTC)
        cert = (
            x509.CertificateBuilder()
            .subject_name(name)
            .issuer_name(name)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - datetime.timedelta(minutes=5))
            .not_valid_after(now + datetime.timedelta(days=3650))
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .add_extension(
                x509.KeyUsage(
                    digital_signature=True,
                    key_encipherment=True,
                    content_commitment=False,
                    data_encipherment=False,
                    key_agreement=False,
                    key_cert_sign=False,
                    crl_sign=False,
                    encipher_only=False,
                    decipher_only=False,
                ),
                critical=True,
            )
            .sign(key, hashes.SHA256())
        )
        keyfile.write_bytes(
            key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption(),
            )
        )
        keyfile.chmod(0o600)
        certfile.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
        return cls(key=key, cert=cert)


def x509_asn1(cert: x509.Certificate) -> a_x509.Certificate:
    """cryptography certificate to asn1crypto certificate"""
    loaded: a_x509.Certificate = a_x509.Certificate.load(cert.public_bytes(serialization.Encoding.DER))
    return loaded


def _degenerate_certs_only(certs: list[x509.Certificate]) -> bytes:
    """A certs-only PKCS#7, which is how SCEP ships both GetCACert and an issued certificate"""
    signed = cms.SignedData(
        {
            "version": "v1",
            "digest_algorithms": [],
            "encap_content_info": {"content_type": "data"},
            "certificates": [cms.CertificateChoices("certificate", x509_asn1(cert)) for cert in certs],
            "signer_infos": [],
        }
    )
    dumped: bytes = cms.ContentInfo({"content_type": "signed_data", "content": signed}).dump()
    return dumped


def _signed_attrs(
    content: bytes,
    transaction_id: str,
    recipient_nonce: bytes,
    status: str,
    fail_info: str | None,
) -> cms.CMSAttributes:
    """The SCEP authenticated attributes that cryptography cannot express"""
    attrs = [
        cms.CMSAttribute({"type": "content_type", "values": ["data"]}),
        cms.CMSAttribute({"type": "message_digest", "values": [hashlib.sha256(content).digest()]}),
        cms.CMSAttribute({"type": "scep_message_type", "values": [MSG_CERT_REP]}),
        cms.CMSAttribute({"type": "scep_pki_status", "values": [status]}),
        cms.CMSAttribute({"type": "scep_transaction_id", "values": [transaction_id]}),
        cms.CMSAttribute({"type": "scep_sender_nonce", "values": [secrets.token_bytes(16)]}),
        cms.CMSAttribute({"type": "scep_recipient_nonce", "values": [recipient_nonce]}),
    ]
    if fail_info is not None:
        attrs.append(cms.CMSAttribute({"type": "scep_fail_info", "values": [fail_info]}))
    return cms.CMSAttributes(attrs)


def _wrap_signed(ra: RaIdentity, content: bytes, attrs: cms.CMSAttributes) -> bytes:
    """Sign `content` with the RA key, carrying `attrs` as authenticated attributes"""
    # The signature covers the attributes DER encoded as an explicit SET OF, not as the implicitly
    # tagged [0] they appear as inside SignerInfo.
    signature = ra.key.sign(attrs.dump(), padding.PKCS1v15(), hashes.SHA256())
    signer = cms.SignerInfo(
        {
            "version": "v1",
            "sid": cms.SignerIdentifier(
                "issuer_and_serial_number",
                cms.IssuerAndSerialNumber(
                    {
                        "issuer": x509_asn1(ra.cert).issuer,
                        "serial_number": ra.cert.serial_number,
                    }
                ),
            ),
            "digest_algorithm": {"algorithm": "sha256"},
            "signed_attrs": attrs,
            "signature_algorithm": {"algorithm": "rsassa_pkcs1v15"},
            "signature": signature,
        }
    )
    signed = cms.SignedData(
        {
            "version": "v1",
            "digest_algorithms": [{"algorithm": "sha256"}],
            "encap_content_info": {"content_type": "data", "content": content},
            "certificates": [cms.CertificateChoices("certificate", x509_asn1(ra.cert))],
            "signer_infos": [signer],
        }
    )
    dumped: bytes = cms.ContentInfo({"content_type": "signed_data", "content": signed}).dump()
    return dumped


def _envelope_for(recipient: x509.Certificate, payload: bytes) -> bytes:
    """Encrypt `payload` to the device's certificate, returning the ContentInfo DER"""
    builder = pkcs7.PKCS7EnvelopeBuilder().set_data(payload).add_recipient(recipient)
    # SCEP's pkcsPKIEnvelope is the whole ContentInfo(EnvelopedData), not a bare EnvelopedData, so
    # this goes in as cryptography hands it back.
    enveloped: bytes = builder.encrypt(serialization.Encoding.DER, [pkcs7.PKCS7Options.Binary])
    return enveloped


@dataclass
class ScepRequest:
    """What we could read out of a device's PKCSReq"""

    transaction_id: str
    sender_nonce: bytes
    device_cert: x509.Certificate
    csr_pem: str
    common_name: str
    challenge: str | None


def _attr_values(signer: cms.SignerInfo) -> dict[str, Any]:
    """The signed attributes of a SignerInfo, by name"""
    return {attr["type"].native: attr["values"] for attr in signer["signed_attrs"]}


def _verify_signer(signer: cms.SignerInfo, device_cert: x509.Certificate) -> None:
    """Check the request was signed by the key in the certificate it carries

    The transaction id and the nonces live in these attributes, and we echo them back. Without this
    they are simply whatever the sender wrote. It is not authentication -- the certificate is
    self-signed by the device and means nothing to us -- it is integrity of the exchange.
    """
    # SHA-1 is deliberately absent. We advertise SHA-256 in GetCACaps and RFC 8894 requires every
    # client to support it, so anything still signing with SHA-1 is old enough that we would
    # rather it failed loudly than be quietly accepted.
    hashers: dict[str, hashes.HashAlgorithm] = {
        "sha256": hashes.SHA256(),
        "sha384": hashes.SHA384(),
        "sha512": hashes.SHA512(),
    }
    digest_algorithm = signer["digest_algorithm"]["algorithm"].native
    if digest_algorithm not in hashers:
        raise ScepError(f"unsupported digest algorithm {digest_algorithm}")
    hasher = hashers[digest_algorithm]
    # RFC 5652 section 5.4: the signature is computed over the attributes DER encoded as an
    # explicit SET OF, not over the implicitly tagged [0] they appear as inside SignerInfo. Getting
    # this wrong rejects every genuine request, which is a long afternoon.
    signed_bytes = signer["signed_attrs"].untag().dump()
    signature = signer["signature"].native
    public_key = device_cert.public_key()
    try:
        if isinstance(public_key, ec.EllipticCurvePublicKey):
            public_key.verify(signature, signed_bytes, ec.ECDSA(hasher))
        elif isinstance(public_key, rsa.RSAPublicKey):
            public_key.verify(signature, signed_bytes, padding.PKCS1v15(), hasher)
        elif isinstance(public_key, ed25519.Ed25519PublicKey):
            public_key.verify(signature, signed_bytes)
        else:
            raise ScepError(f"unsupported key type {type(public_key).__name__}")
    except (InvalidSignature, TypeError, ValueError) as exc:
        raise ScepError("the request signature does not verify", FAIL_BAD_IDENTITY) from exc


def parse_pkcs_req(body: bytes, ra: RaIdentity) -> ScepRequest:
    """Unwrap SignedData, then EnvelopedData, then PKCS#10, and read the SCEP attributes"""
    if len(body) > MAX_REQUEST_BYTES:
        raise ScepError(f"request of {len(body)} bytes is larger than we answer")
    try:
        info = cms.ContentInfo.load(body)
        if info["content_type"].native != "signed_data":
            raise ScepError("not a SignedData")
        signed = info["content"]
        signer = signed["signer_infos"][0]
        attrs = _attr_values(signer)
    except ScepError:
        raise
    except Exception as exc:
        raise ScepError(f"could not parse the request: {exc}") from exc

    # These read attributes a caller chose, and they are reachable with no crypto at all: a handful
    # of DER bytes with no transactionID is enough. A missing attribute raises KeyError and one
    # carrying an empty SET OF raises IndexError, so both have to become refusals here rather than
    # a traceback and a 500 on an internet facing endpoint.
    try:
        message_type = attrs.get("scep_message_type", [None])[0]
        if message_type is None or message_type.native != MSG_PKCS_REQ:
            raise ScepError("only PKCSReq is supported")
        transaction_id = str(attrs["scep_transaction_id"][0].native)
        sender_nonce = bytes(attrs["scep_sender_nonce"][0].native)
    except ScepError:
        raise
    except Exception as exc:
        raise ScepError(f"the request is missing a SCEP attribute: {exc}") from exc

    certs = [choice.chosen for choice in signed["certificates"]] if signed["certificates"] else []
    if not certs:
        raise ScepError("request carried no device certificate to reply to")
    try:
        device_cert = x509.load_der_x509_certificate(certs[0].dump())
    except Exception as exc:
        raise ScepError(f"the request's device certificate does not parse: {exc}") from exc
    _verify_signer(signer, device_cert)

    # The content is the pkcsPKIEnvelope: a complete ContentInfo(EnvelopedData). Re-encode it as
    # strict DER before decrypting. pkcs7_decrypt_der is backed by a strict DER parser, but real
    # SCEP clients built on BouncyCastle (jscep, and therefore the Fleet Android agent) emit BER
    # with indefinite length constructed encoding, which it rejects with
    # "error parsing asn1 value: ParseError { kind: InvalidLength }". asn1crypto reads both, and
    # force=True makes it write canonical DER. A no-op for input that was already DER.
    enveloped = signed["encap_content_info"]["content"].native
    try:
        enveloped = cms.ContentInfo.load(enveloped).dump(force=True)
    except Exception as exc:
        raise ScepError(f"could not parse the request envelope: {exc}") from exc
    try:
        csr_der = pkcs7.pkcs7_decrypt_der(enveloped, ra.cert, ra.key, [])
    except Exception as exc:
        raise ScepError(f"could not decrypt the request: {exc}") from exc

    # Everything from here reads bytes an unauthenticated caller chose. They decrypted, which only
    # means they had our public key, so they still have to be treated as hostile: an uncaught
    # exception here is a 500 on an internet facing endpoint rather than a refusal.
    try:
        csr = x509.load_der_x509_csr(csr_der)
        signature_ok = csr.is_signature_valid
    except Exception as exc:
        raise ScepError(f"the request did not contain a certificate request: {exc}") from exc
    if not signature_ok:
        raise ScepError("the certificate request signature does not verify", FAIL_BAD_IDENTITY)
    try:
        common_names = csr.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
    except Exception as exc:
        raise ScepError(f"could not read the request subject: {exc}") from exc
    if len(common_names) != 1 or not str(common_names[0].value).strip():
        # An MDM whose subject template has not been filled in yet sends an empty CN. Refusing here
        # means we never ask RASENMAEHER about a callsign nobody could have planned.
        raise ScepError("the certificate request has no single usable common name", FAIL_BAD_IDENTITY)

    challenge: str | None = None
    try:
        attributes = list(csr.attributes)
    except Exception as exc:
        # cryptography raises on duplicate or malformed attributes, and a client controls these
        raise ScepError(f"could not read the request attributes: {exc}") from exc
    for attribute in attributes:
        if attribute.oid.dotted_string == OID_CHALLENGE_PASSWORD:
            challenge = attribute.value.decode("utf-8", errors="replace")

    return ScepRequest(
        transaction_id=transaction_id,
        sender_nonce=sender_nonce,
        device_cert=device_cert,
        csr_pem=csr.public_bytes(serialization.Encoding.PEM).decode("utf-8"),
        common_name=str(common_names[0].value),
        challenge=challenge,
    )


def cert_rep(ra: RaIdentity, req: ScepRequest, issued_pem: str) -> bytes:
    """A successful CertRep carrying the issued certificate"""
    issued = x509.load_pem_x509_certificates(issued_pem.encode("utf-8"))
    payload = _envelope_for(req.device_cert, _degenerate_certs_only(issued))
    attrs = _signed_attrs(payload, req.transaction_id, req.sender_nonce, STATUS_SUCCESS, None)
    return _wrap_signed(ra, payload, attrs)


def failure_rep(ra: RaIdentity, transaction_id: str, sender_nonce: bytes, fail_info: str) -> bytes:
    """A CertRep saying no, so the device stops retrying instead of hanging"""
    attrs = _signed_attrs(b"", transaction_id, sender_nonce, STATUS_FAILURE, fail_info)
    return _wrap_signed(ra, b"", attrs)


def ca_cert_response(ra: RaIdentity, ca_pems: list[bytes]) -> bytes:
    """GetCACert: the RA certificate devices encrypt to, plus the chain they must trust"""
    certs = [ra.cert]
    for pem in ca_pems:
        certs.extend(x509.load_pem_x509_certificates(pem))
    return _degenerate_certs_only(certs)
