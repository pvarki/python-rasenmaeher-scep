"""CLI entrypoints for rmscep"""

import datetime
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

from . import config, mdmtemplate
from .mdm import FleetError, FleetMdm
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


@cli_group.command(name="obtain-cert")
@click.pass_context
@click.option("--signer-url", required=True, help="Base URL of the deployment's CSR signer")
@click.option("--common-name", default="rmscep", help="CN to request, must match rasenmaeher's RM_MDM_AGENT_CNS")
@click.option("--keyfile", default=None, help="Where to write the private key (default: RMSCEP_KEY)")
@click.option("--certfile", default=None, help="Where to write the certificate (default: RMSCEP_CERT)")
@click.option("--force", is_flag=True, help="Replace an identity that already exists")
@click.option(
    "--renew-before-days",
    default=14,
    show_default=True,
    help="Replace the identity when it expires within this many days",
)
def obtain_cert(  # pylint: disable=too-many-arguments,too-many-positional-arguments
    ctx: click.Context,
    signer_url: str,
    common_name: str,
    keyfile: str | None,
    certfile: str | None,
    force: bool,
    renew_before_days: int,
) -> None:
    """Get our client identity signed by the deployment CA, then exit

    Meant for a one shot init container that can reach the signer, so the long running service
    never needs to: something that can ask for a certificate for an arbitrary subject is not a
    privilege an internet facing parser should hold for its whole life.

    Idempotent -- an identity that is still good is left alone, so restarting the stack does not
    churn certificates. One that is expired or close to it is replaced, because nothing renews it
    while the container keeps running and the signed lifetime is far shorter than the uptime we
    would like.
    """
    target_key = Path(keyfile) if keyfile else config.KEY
    target_cert = Path(certfile) if certfile else config.CERT
    if not target_key or not target_cert:
        click.echo("Give --keyfile and --certfile, or set RMSCEP_KEY and RMSCEP_CERT", err=True)
        ctx.exit(1)
        return
    if target_key.is_file() and target_cert.is_file() and not force:
        remaining = _days_left(target_cert)
        if remaining is None:
            click.echo(f"Identity in {target_cert} does not parse, replacing it")
        elif remaining > renew_before_days:
            click.echo(f"Identity already in {target_cert}, valid {remaining}d, nothing to do")
            ctx.exit(0)
            return
        else:
            click.echo(f"Identity in {target_cert} expires in {remaining}d, renewing")

    key = ec.generate_private_key(ec.SECP256R1())
    csr = (
        x509.CertificateSigningRequestBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)]))
        .sign(key, hashes.SHA256())
    )
    csrpem = csr.public_bytes(serialization.Encoding.PEM).decode("utf-8")

    url = f"{signer_url.rstrip('/')}/api/v1/csr/sign"
    try:
        response = httpx.post(
            url,
            json={"certificate_request": csrpem, "profile": "client", "bundle": True},
            timeout=30.0,
        )
        response.raise_for_status()
        # The signer escapes the newlines, as CFSSL conventions do throughout this platform.
        certpem = str(response.json()["result"]["certificate"]).replace("\\n", "\n")
    except (httpx.HTTPError, KeyError, ValueError) as exc:
        click.echo(f"Could not get a certificate from {url}: {exc}", err=True)
        ctx.exit(1)
        return

    target_key.parent.mkdir(parents=True, exist_ok=True)
    target_cert.parent.mkdir(parents=True, exist_ok=True)
    target_key.write_bytes(
        key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
    )
    target_key.chmod(0o600)
    target_cert.write_text(certpem, encoding="utf-8")
    issued = x509.load_pem_x509_certificate(certpem.encode("utf-8"))
    click.echo(f"Got {issued.subject.rfc4514_string()} valid until {issued.not_valid_after_utc.date()}")
    ctx.exit(0)


def rmscep_cli() -> None:
    """CLI entrypoint"""
    cli_group()  # pylint: disable=no-value-for-parameter


def _days_left(certfile: Path) -> int | None:
    """Whole days until the certificate expires, or None if it cannot be read

    Negative once it has expired, so the caller renews on the same branch.
    """
    try:
        cert = x509.load_pem_x509_certificate(certfile.read_bytes())
    except (ValueError, OSError) as exc:
        LOGGER.warning("Could not read %s: %s", certfile, exc)
        return None
    return (cert.not_valid_after_utc - datetime.datetime.now(datetime.UTC)).days


@cli_group.command(name="mdm-apply")
@click.pass_context
@click.option("--template", default=None, help="The document saying what to install (default: RMSCEP_MDM_TEMPLATE)")
@click.option("--mdm-url", default=None, help="Base URL of the MDM API (default: RMSCEP_MDM_URL)")
@click.option("--team", default=None, help="The group devices join (default: RMSCEP_MDM_TEAM)")
@click.option("--domain", default=None, help="The deployment's DNS name (default: RMSCEP_DOMAIN)")
@click.option(
    "--force-policy", is_flag=True, help="Re-upload the policy even if unchanged, to reach a host that just joined"
)
@click.option("--dry-run", is_flag=True, help="Read and validate the template, then stop")
def mdm_apply(  # pylint: disable=too-many-arguments,too-many-positional-arguments
    ctx: click.Context,
    template: str | None,
    mdm_url: str | None,
    team: str | None,
    domain: str | None,
    force_policy: bool,
    dry_run: bool,
) -> None:
    """Tell the MDM what this deployment's devices need

    An operator runs this when a deployment is set up or its template changes. It is deliberately
    not part of the responder: something holding an MDM's API token has no business also being an
    internet facing parser.

    Order matters and is handled for you. Apps install at ENROLMENT and at no other time, so a
    device that has already joined will not pick up a template applied afterwards -- it has to
    enrol again, under a callsign that has not been spent.
    """
    path = Path(template) if template else config.MDM_TEMPLATE
    the_domain = domain or config.DOMAIN
    if not path:
        click.echo("Give --template or set RMSCEP_MDM_TEMPLATE", err=True)
        ctx.exit(1)
        return
    if not the_domain:
        click.echo("Give --domain or set RMSCEP_DOMAIN", err=True)
        ctx.exit(1)
        return

    try:
        wanted = mdmtemplate.load(path, domain=the_domain, key_alias=config.KEY_ALIAS)
    except mdmtemplate.TemplateError as exc:
        click.echo(f"Template refused: {exc}", err=True)
        ctx.exit(1)
        return

    click.echo(f"Template names {len(wanted.apps)} apps, {len(wanted.preinstall_packages)} installed at enrolment")
    for app in wanted.apps:
        click.echo(f"  {app.package}{' (at enrolment)' if app.preinstall else ' (on demand)'}")
    if wanted.link_app:
        click.echo(f"  launcher link {wanted.link_app.title!r} -> {wanted.link_app.url}")
    if dry_run:
        ctx.exit(0)
        return

    url = mdm_url or config.MDM_URL
    if not url:
        click.echo("Give --mdm-url or set RMSCEP_MDM_URL", err=True)
        ctx.exit(1)
        return
    if not config.MDM_TOKEN_FILE or not config.MDM_TOKEN_FILE.is_file():
        click.echo("Set RMSCEP_MDM_TOKEN_FILE to a file holding the MDM API token", err=True)
        ctx.exit(1)
        return
    token = config.MDM_TOKEN_FILE.read_text(encoding="utf-8").strip()

    try:
        result = FleetMdm(url, token).apply(team or config.MDM_TEAM, wanted, force_policy=force_policy)
    except FleetError as exc:
        click.echo(f"The MDM refused: {exc}", err=True)
        ctx.exit(1)
        return
    click.echo(f"Applied to team {result['team_id']}: {len(result['assigned'])} apps assigned")
    ctx.exit(0)
