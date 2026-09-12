"""CLI entrypoints for rmscep"""

import logging
import sys
from pathlib import Path

import click
import httpx
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID
from libadvian.logging import init_logging

from rmscep import __version__

from . import config
from .scep import RaIdentity

LOGGER = logging.getLogger(__name__)


@click.group()
@click.version_option(version=__version__)
@click.pass_context
@click.option("-v", "--verbose", count=True, help="Shorthand for info/debug loglevel (-v/-vv)")
def cli_group(ctx: click.Context, verbose: int) -> None:
    """CLI helpers for the RASENMAEHER SCEP responder"""
    _ = ctx
    loglevel = config.LOG_LEVEL
    if verbose == 1:
        loglevel = 20
    if verbose >= 2:
        loglevel = 10
    init_logging(loglevel)
    LOGGER.setLevel(loglevel)


@cli_group.command(name="healthcheck")
@click.pass_context
@click.option("--port", default=8000, help="Port the service listens on")
def healthcheck(ctx: click.Context, port: int) -> None:
    """Ask ourselves whether we are healthy, for the container healthcheck"""
    try:
        response = httpx.get(f"http://localhost:{port}/api/v1/healthcheck", timeout=5.0)
    except httpx.HTTPError as exc:
        click.echo(f"unreachable: {exc}", err=True)
        ctx.exit(1)
        return
    payload = response.json()
    click.echo(f"{response.status_code}: {payload}")
    ctx.exit(0 if response.status_code == 200 and payload.get("healthy") else 1)


@cli_group.command(name="init-ra")
@click.pass_context
def init_ra(ctx: click.Context) -> None:
    """Create the SCEP RA identity if it does not exist yet

    Run this in the entrypoint, before the web workers start. Workers racing each other on an empty
    directory would each generate a key and only one of them would be the one devices encrypt to.
    """
    identity = RaIdentity.load_or_create(config.ra_dir())
    click.echo(f"RA identity in {config.ra_dir()}, serial {identity.cert.serial_number}")
    ctx.exit(0)


@cli_group.command(name="client-csr")
@click.pass_context
@click.option("--common-name", default="rmscep", help="CN to request, must match rasenmaeher's RM_MDM_AGENT_CNS")
@click.option("--keyfile", default=None, help="Where to write the private key (default: RMSCEP_KEY)")
@click.option("--csrfile", default=None, help="Where to write the request, - for stdout")
def client_csr(ctx: click.Context, common_name: str, keyfile: str | None, csrfile: str | None) -> None:
    """Generate our client key and a certificate request for the deployment CA to sign

    This is the identity we authenticate to RASENMAEHER with. The key is a P-256 curve: nothing in
    this path needs RSA, both cfssl and cert-manager sign ECDSA happily, and it is the smaller and
    faster of the two. (The SCEP RA key is RSA and has to be -- see RaIdentity for why.)

    The key never leaves this container. Feed the request to whatever signs for the deployment.
    """
    target_key = Path(keyfile) if keyfile else config.KEY
    if not target_key:
        click.echo("Give --keyfile or set RMSCEP_KEY", err=True)
        ctx.exit(1)
        return

    key = ec.generate_private_key(ec.SECP256R1())
    target_key.parent.mkdir(parents=True, exist_ok=True)
    target_key.write_bytes(
        key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
    )
    target_key.chmod(0o600)

    csr = (
        x509.CertificateSigningRequestBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)]))
        .sign(key, hashes.SHA256())
    )
    csrpem = csr.public_bytes(serialization.Encoding.PEM).decode("utf-8")
    if csrfile in (None, "-"):
        sys.stdout.write(csrpem)
    else:
        Path(str(csrfile)).write_text(csrpem, encoding="utf-8")
    LOGGER.info("Wrote the client key to %s", target_key)
    ctx.exit(0)


def rmscep_cli() -> None:
    """CLI entrypoint"""
    cli_group()  # pylint: disable=no-value-for-parameter
