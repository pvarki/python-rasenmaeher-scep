"""The FleetDM dialect

Every request shape and every wait in here was measured against a live Fleet, and the comments
say which. None of it mentions a product: what to install arrives in the template.
"""

import hashlib
import json
import logging
import time
from typing import Any
from urllib.parse import urlencode

import httpx

from ..mdmtemplate import MdmTemplate
from .icon import launcher_icon

LOGGER = logging.getLogger(__name__)

#: A web app is not installable until managed Play has published it, which is not synchronous
WEB_APP_PUBLISH_ATTEMPTS = 12
WEB_APP_PUBLISH_WAIT = 10.0


class FleetError(RuntimeError):
    """Fleet refused, or answered something we cannot use"""


class FleetMdm:
    """What this feature needs an MDM to be able to do, in Fleet's words"""

    def __init__(self, base_url: str, token: str, timeout: float = 60.0) -> None:
        self.base_url = base_url.rstrip("/")
        self._token = token
        self.timeout = timeout
        #: What we last uploaded, so an unchanged policy is not rewritten. Re-pushing on every
        #: pass is not merely wasteful: a policy rewritten repeatedly never settles long enough
        #: for Play to finish an install, and the device comes up with nothing on it.
        self._pushed: dict[str, str] = {}

    def _call(self, method: str, path: str, body: dict[str, Any] | None = None) -> dict[str, Any]:
        url = f"{self.base_url}{path}"
        try:
            response = httpx.request(
                method,
                url,
                json=body,
                headers={"Authorization": f"Bearer {self._token}"},
                timeout=self.timeout,
            )
        except httpx.HTTPError as exc:
            raise FleetError(f"could not reach the MDM: {exc}") from exc
        if response.status_code >= 400:
            # Enough of the body to keep the reason intact: the retry below matches on it, and
            # truncating to a couple of hundred characters cut the phrase off mid-word.
            raise FleetError(f"{method} {path} answered {response.status_code}: {response.text[:800]}")
        if not response.content:
            return {}
        try:
            payload: dict[str, Any] = response.json()
        except ValueError as exc:
            raise FleetError(f"{method} {path} did not answer JSON") from exc
        return payload

    def _upload(
        self,
        path: str,
        fields: dict[str, str],
        filename: str,
        payload: bytes,
        file_field: str,
        content_type: str = "application/json",
    ) -> dict[str, Any]:
        url = f"{self.base_url}{path}"
        try:
            response = httpx.post(
                url,
                data=fields,
                files={file_field: (filename, payload, content_type)},
                headers={"Authorization": f"Bearer {self._token}"},
                timeout=self.timeout,
            )
        except httpx.HTTPError as exc:
            raise FleetError(f"could not reach the MDM: {exc}") from exc
        if response.status_code >= 400:
            raise FleetError(f"upload to {path} answered {response.status_code}: {response.text[:200]}")
        return response.json() if response.content else {}

    # --- scopes ---------------------------------------------------------------

    def team_id(self, name: str) -> int:
        """The team by name, created if it is not there yet"""
        for team in self._call("GET", "/api/latest/fleet/teams").get("teams", []):
            if team.get("name") == name:
                return int(team["id"])
        created = self._call("POST", "/api/latest/fleet/teams", {"name": name})
        team = created.get("team", created)
        LOGGER.info("Created team %s", name)
        return int(team["id"])

    # --- what a device gets ---------------------------------------------------

    def _title_id(self, team: int, package: str) -> int | None:
        query = urlencode({"team_id": team, "available_for_install": "true"})
        titles = self._call("GET", f"/api/latest/fleet/software/titles?{query}").get("software_titles", [])
        for title in titles:
            if (title.get("app_store_app") or {}).get("app_store_id") == package:
                return int(title["id"])
        return None

    def assign_apps(self, team: int, packages: list[str], preinstall: list[str]) -> dict[str, int]:
        """Make the apps available, and install them at enrolment where that is possible

        Fleet hardcodes AVAILABLE for user-added Android apps -- FORCE_INSTALLED is reserved for
        its own agent -- so the setup experience is the only automatic path, and it applies at
        ENROLMENT. A host that has already joined will never auto-install; it has to enrol again.
        """
        ids: dict[str, int] = {}
        for package in packages:
            existing = self._title_id(team, package)
            if existing:
                ids[package] = existing
                continue
            body = {"app_store_id": package, "platform": "android", "team_id": team}
            for attempt in range(WEB_APP_PUBLISH_ATTEMPTS):
                try:
                    created = self._call("POST", "/api/latest/fleet/software/app_store_apps", body)
                    ids[package] = int(created["software_title_id"])
                    break
                except FleetError as exc:
                    # Apostrophes vary; match the part that does not.
                    if "available in Play Store" not in str(exc) or attempt == WEB_APP_PUBLISH_ATTEMPTS - 1:
                        raise
                    LOGGER.info("Waiting for managed Play to publish %s", package)
                    time.sleep(WEB_APP_PUBLISH_WAIT)
        chosen = sorted(ids[p] for p in preinstall if p in ids)
        digest = hashlib.sha256(repr(chosen).encode()).hexdigest()
        if chosen and self._pushed.get(f"{team}:setup") != digest:
            self._call(
                "PUT",
                "/api/latest/fleet/setup_experience/software",
                {"platform": "android", "team_id": team, "software_title_ids": chosen},
            )
            self._pushed[f"{team}:setup"] = digest
        return ids

    def set_app_config(self, team: int, package: str, config: dict[str, Any]) -> None:
        title = self._title_id(team, package)
        if not title:
            raise FleetError(f"{package} is not assigned to team {team}; assign it before configuring it")
        self._call(
            "PATCH",
            f"/api/latest/fleet/software/titles/{title}/app_store_app",
            {"team_id": team, "configuration": {"managedConfiguration": config}},
        )

    def ensure_policy(
        self, team: int, fragment: dict[str, Any], name: str = "rmscep-policy", force: bool = False
    ) -> None:
        """Android configuration profiles carry raw policy JSON

        There is no update in place, so changing one is delete then upload, and the single
        profile GET returns metadata only, so there is nothing to compare against -- remember the
        digest instead. Re-uploading an unchanged profile is not free: a policy rewritten on every
        pass never settles long enough for Play to finish an install.

        force exists because a profile is delivered when the PROFILE changes, not when a host
        arrives, so one created before a device joined is never sent to it.
        """
        profiles = self._call("GET", f"/api/latest/fleet/configuration_profiles?team_id={team}").get("profiles", [])
        wanted = json.dumps(fragment, indent=2, sort_keys=True).encode("utf-8")
        digest = hashlib.sha256(wanted).hexdigest()
        here = [p for p in profiles if p.get("name") == name]
        if here and not force and self._pushed.get(f"{team}:{name}") == digest:
            return
        for existing in here:
            self._call("DELETE", f"/api/latest/fleet/configuration_profiles/{existing['profile_uuid']}")
        self._upload(
            "/api/latest/fleet/configuration_profiles",
            {"team_id": str(team)},
            f"{name}.json",
            wanted,
            file_field="profile",
        )
        self._pushed[f"{team}:{name}"] = digest
        LOGGER.info("Uploaded policy %s to team %s", name, team)

    def ensure_link_app(self, team: int, title: str, url: str) -> str:
        """A managed web app, so the deployment has an icon on the launcher

        Reused if one is already there: Fleet has no API to list or delete web apps, so a second
        one would be permanent litter in the enterprise. The icon is required rather than
        decorative -- without one Google never publishes the app and every device reports the
        install as NOT_FOUND.
        """
        for team_row in self._call("GET", "/api/latest/fleet/teams").get("teams", []):
            query = urlencode({"team_id": team_row["id"], "available_for_install": "true"})
            for existing in self._call("GET", f"/api/latest/fleet/software/titles?{query}").get("software_titles", []):
                package = (existing.get("app_store_app") or {}).get("app_store_id", "")
                if package.startswith("com.google.enterprise.webapp.") and existing.get("name") == title:
                    return str(package)
        created = self._upload(
            "/api/latest/fleet/software/web_apps",
            {"title": title, "url": url},
            "icon.png",
            launcher_icon(),
            file_field="icon",
            content_type="image/png",
        )
        package = str(created.get("app_store_id") or created.get("package_name") or "")
        if not package:
            raise FleetError(f"the MDM did not name the web app it created: {created}")
        LOGGER.info("Created the launcher web app %s", package)
        return package

    def ensure_certificate(
        self, team: int, name: str, subject: str, authority: str, force: bool = False
    ) -> int:
        """The template the MDM fills in per device, and asks us to sign

        There is no update in place, so a changed subject is delete then create. The name is kept
        because it becomes the Android keystore alias, and a device already holding a key under one
        alias will not accept a second.

        force exists because the subject is filled in when a device ENROLS, and a device enrols
        before anyone has named it -- the host does not exist to be named until then. That first
        attempt fails, and Fleet never retries a failed certificate on its own. Recreating the
        template is what asks again, so it is how a named host finally gets its certificate.
        """
        authorities = self._call("GET", "/api/latest/fleet/certificate_authorities").get("certificate_authorities", [])
        match = [a for a in authorities if a.get("name") == authority]
        if not match:
            known = ", ".join(sorted(str(a.get("name")) for a in authorities)) or "none"
            raise FleetError(f"no certificate authority named {authority!r}; the MDM has: {known}")
        authority_id = int(match[0]["id"])

        existing = self._call("GET", f"/api/latest/fleet/certificates?team_id={team}").get("certificates", [])
        for template in existing:
            if template.get("name") != name:
                continue
            if (
                not force
                and template.get("subject_name") == subject
                and int(template.get("certificate_authority_id", 0)) == authority_id
            ):
                return int(template["id"])
            self._call("DELETE", f"/api/latest/fleet/certificates/{template['id']}?team_id={team}")
            LOGGER.info("Replacing certificate template %s, so it is asked for again", name)

        created = self._call(
            "POST",
            "/api/latest/fleet/certificates",
            {"name": name, "team_id": team, "certificate_authority_id": authority_id, "subject_name": subject},
        )
        LOGGER.info("Certificate template %s asks for %s", name, subject)
        return int(created["id"])

    def hosts_awaiting_certificate(self, team: int, name: str) -> list[int]:
        """Hosts that were named after they enrolled, and so have no certificate

        The subject is filled in when a device ENROLS, and a device enrols before anyone has named
        it -- there is no host to name until it does. That first attempt fails, and nothing retries
        it. These are the hosts for which asking again would now work: named, and still refused.

        Asking again is not free, because it re-asks every device in the group, so this exists to
        keep that to the occasions when it would change something.
        """
        hosts = self._call("GET", f"/api/latest/fleet/hosts?team_id={team}&per_page=500").get("hosts") or []
        waiting = []
        for host in hosts:
            host_id = int(host["id"])
            detail = self._call("GET", f"/api/latest/fleet/hosts/{host_id}").get("host") or {}
            profiles = (detail.get("mdm") or {}).get("profiles") or []
            if not any(p.get("name") == name and p.get("status") == "failed" for p in profiles):
                continue
            mapping = (
                self._call("GET", f"/api/latest/fleet/hosts/{host_id}/device_mapping").get("device_mapping") or []
            )
            if any(entry.get("email") for entry in mapping):
                waiting.append(host_id)
        return waiting

    # --- the whole statement --------------------------------------------------

    def apply(
        self,
        team_name: str,
        template: MdmTemplate,
        force_policy: bool = False,
        force_certificate: bool = False,
    ) -> dict[str, Any]:
        """State everything the template says, in the order that actually works

        The policy goes in BEFORE the apps: a permission grant only applies to an app that
        installs while it is already in force, and the key selection rules are what make the
        certificate visible to anything at all. Both have to be true before a device joins,
        because that is the only moment apps install.
        """
        team = self.team_id(team_name)
        if template.certificate:
            self.ensure_certificate(
                team,
                template.certificate.name,
                template.certificate.subject,
                template.certificate.authority,
                force=force_certificate,
            )
        self.ensure_policy(team, template.policy, force=force_policy)

        packages = [app.package for app in template.apps]
        preinstall = list(template.preinstall_packages)
        if template.link_app:
            link = self.ensure_link_app(team, template.link_app.title, template.link_app.url)
            packages.append(link)
            preinstall.append(link)

        assigned = self.assign_apps(team, packages, preinstall)
        for app in template.apps:
            if app.config:
                self.set_app_config(team, app.package, app.config)
        return {"team_id": team, "assigned": sorted(assigned), "preinstall": sorted(preinstall)}
