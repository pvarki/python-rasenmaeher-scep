"""What a device needs, read from a file rather than known here

This module deliberately contains no package name, no managed-configuration key and no product
of any kind. What a deployment installs is a property of that deployment, not of the responder,
and the responder is meant to be detachable and short lived. So the whole answer arrives as a
document an operator supplies and this module only validates it and fills in the deployment's own
values.

The placeholders are the only vocabulary shared with the document:

``{domain}``     the deployment's DNS name
``{mtls_url}``   where a client certificate is expected, ``https://mtls.<domain>``
``{key_alias}``  the Android keystore alias the certificate lands under, which is the name of the
                 MDM certificate template, because installing a second key under an existing alias
                 fails
"""

import json
import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

LOGGER = logging.getLogger(__name__)


class TemplateError(ValueError):
    """The document is not something we can act on"""


@dataclass(frozen=True)
class App:
    """One application the deployment wants on its devices"""

    package: str
    #: Install it as part of enrolment rather than leaving it available on demand. On managed
    #: Android this is the only automatic path, and it applies at enrolment only.
    preinstall: bool = True
    #: Managed configuration for the app, already substituted
    config: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class LinkApp:
    """A managed web app, so the deployment has an icon on the launcher"""

    title: str
    url: str


@dataclass(frozen=True)
class MdmTemplate:
    """Everything to state to an MDM about one deployment"""

    apps: tuple[App, ...]
    policy: dict[str, Any]
    link_app: LinkApp | None = None

    @property
    def preinstall_packages(self) -> tuple[str, ...]:
        return tuple(app.package for app in self.apps if app.preinstall)


def _substitute(value: Any, values: dict[str, str]) -> Any:
    """Fill the placeholders wherever they appear, at any depth"""
    if isinstance(value, str):
        for key, replacement in values.items():
            value = value.replace("{" + key + "}", replacement)
        return value
    if isinstance(value, dict):
        return {key: _substitute(item, values) for key, item in value.items()}
    if isinstance(value, list):
        return [_substitute(item, values) for item in value]
    return value


def load(path: Path, domain: str, key_alias: str) -> MdmTemplate:
    """Read the document and fill in this deployment's values

    Raises TemplateError rather than letting a malformed document reach the MDM, because a half
    applied template is worse than none: apps install at enrolment only, so a device that joins
    against a broken one has to be enrolled again.
    """
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except OSError as exc:
        raise TemplateError(f"cannot read {path}: {exc}") from exc
    except ValueError as exc:
        raise TemplateError(f"{path} is not valid JSON: {exc}") from exc
    if not isinstance(raw, dict):
        raise TemplateError(f"{path} must contain an object")

    values = {"domain": domain, "mtls_url": f"https://mtls.{domain}", "key_alias": key_alias}
    raw = _substitute(raw, values)

    apps: list[App] = []
    for entry in raw.get("apps", []):
        if not isinstance(entry, dict) or not entry.get("package"):
            raise TemplateError(f"every app needs a package, got {entry!r}")
        config = entry.get("config", {})
        if not isinstance(config, dict):
            raise TemplateError(f"config for {entry['package']} must be an object")
        apps.append(App(package=str(entry["package"]), preinstall=bool(entry.get("preinstall", True)), config=config))
    if not apps:
        raise TemplateError("the template installs nothing; at least one app is required")

    policy = raw.get("policy", {})
    if not isinstance(policy, dict):
        raise TemplateError("policy must be an object")

    link = None
    if raw.get("link_app"):
        entry = raw["link_app"]
        if not isinstance(entry, dict) or not entry.get("title") or not entry.get("url"):
            raise TemplateError("link_app needs a title and a url")
        link = LinkApp(title=str(entry["title"]), url=str(entry["url"]))

    LOGGER.info(
        "Template names %s apps, %s of them installed at enrolment", len(apps), len([a for a in apps if a.preinstall])
    )
    return MdmTemplate(apps=tuple(apps), policy=policy, link_app=link)
