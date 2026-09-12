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
CA_CHAIN_PATH: Path = cfg("CA_CHAIN_PATH", cast=Path, default=Path("/ca_public/ca_chain.pem"))

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
