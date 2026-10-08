"""Configuration, from the environment

Every setting is prefixed RMSCEP_, as RM_ is for rasenmaeher-api and TI_ for tak-rmapi.
"""

from pathlib import Path

from starlette.config import Config

# not supporting .env files, see https://github.com/encode/starlette/discussions/2446
cfg = Config(env_prefix="RMSCEP_")

LOG_LEVEL: int = cfg("LOG_LEVEL", cast=int, default=20)

#: Where RASENMAEHER answers. In compose this is the mTLS host through the front proxy, which
#: validates our client certificate and passes the DN on. In the mesh it is the service, and the
#: mesh carries our identity instead.
RMAPI_URL: str = cfg("RMAPI_URL", cast=str, default="")

#: Our client certificate and its key, issued by the deployment CA. The CN has to be listed in
#: rasenmaeher-api's RM_MDM_AGENT_CNS or it may not complete anything. Unset in a meshed
#: deployment, where the mesh proves who we are.
CERT: Path | None = cfg("CERT", cast=Path, default=None)
KEY: Path | None = cfg("KEY", cast=Path, default=None)

#: What the MDM must present in the certificate request. Not a secret: it sits in the MDM's own
#: configuration and travels in every device's request. It keeps noise off the endpoint; the
#: control is that an admin planned the callsign.
CHALLENGE: str = cfg("CHALLENGE", cast=str, default="")

#: The deployment's CA chain, handed to devices in GetCACert so they trust what they are issued.
#: This is about what the DEVICE trusts. It is deliberately not used to verify RASENMAEHER's own
#: TLS: the front proxy serves a public certificate, so trusting only this would refuse it.
CA_CHAIN_PATH: Path = cfg("CA_CHAIN_PATH", cast=Path, default=Path("/ca_public/ca_chain.pem"))

#: What verifies RASENMAEHER's server certificate. Empty means the system trust store, which is
#: what the public mTLS host needs. Set it to a PEM only where RASENMAEHER is reached on a name
#: whose certificate the system store does not know.
RMAPI_CA: Path | None = cfg("RMAPI_CA", cast=Path, default=None)

#: Persistent state. Only ever the RA identity.
DATA_DIR: Path = cfg("DATA_DIR", cast=Path, default=Path("/data/persistent"))

#: Seconds. Completing an enrolment makes RASENMAEHER call the CA and create a Keycloak user
#: before it answers, so this is not a snappy request.
RMAPI_TIMEOUT: float = cfg("RMAPI_TIMEOUT", cast=float, default=60.0)

#: Where the SCEP endpoints live. The front proxy sends /scep here.
SCEP_PATH: str = cfg("SCEP_PATH", cast=str, default="/scep")


def ra_dir() -> Path:
    """Directory holding the RA identity"""
    return DATA_DIR / "ra"


# --- the MDM side -------------------------------------------------------------------------
# Used only by the `rmscep mdm` commands, which an operator runs when a deployment is set up or
# changes. The responder itself never talks to an MDM and must not hold its token.

#: Where the MDM's API answers
MDM_URL: str = cfg("MDM_URL", cast=str, default="")

#: A file holding the MDM API token. A path rather than the value, so it can be a mounted secret
#: and never appears in the process environment of an internet facing service.
MDM_TOKEN_FILE: Path | None = cfg("MDM_TOKEN_FILE", cast=Path, default=None)

#: The group every device of this deployment joins. Fleet calls it a team.
MDM_TEAM: str = cfg("MDM_TEAM", cast=str, default="rmscep")

#: What this deployment wants installed, as a document. Deliberately not known in code: what a
#: deployment installs is a property of that deployment. See rmscep.mdmtemplate.
MDM_TEMPLATE: Path | None = cfg("MDM_TEMPLATE", cast=Path, default=None)

#: The deployment's DNS name, which the template substitutes into URLs
DOMAIN: str = cfg("DOMAIN", cast=str, default="")

#: The MDM certificate template name, which becomes the Android keystore alias the certificate
#: lands under. Installing a second key under an existing alias fails, so this is per deployment.
KEY_ALIAS: str = cfg("KEY_ALIAS", cast=str, default="rmscep")
