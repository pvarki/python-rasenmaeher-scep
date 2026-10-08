"""The MDM dialect, against a stubbed transport

What matters here is the ORDER and the restraint: the policy has to be in force before anything
installs, and an unchanged policy must not be re-uploaded, because a policy rewritten on every
pass never settles long enough for the device to finish installing anything.
"""

import json
from typing import Any

import httpx
import pytest

from rmscep.mdm import FleetError, FleetMdm
from rmscep.mdm.icon import launcher_icon
from rmscep.mdmtemplate import App, Certificate, LinkApp, MdmTemplate

TEMPLATE = MdmTemplate(
    apps=(
        App(package="com.example.one", preinstall=True, config={"k": "v"}),
        App(package="com.example.two", preinstall=False),
    ),
    policy={"defaultPermissionPolicy": "GRANT"},
)


class _Fleet:
    """A Fleet that records what it was told, in order"""

    def __init__(self) -> None:
        self.calls: list[tuple[str, str]] = []
        self.titles: list[dict[str, Any]] = []
        self.profiles: list[dict[str, Any]] = []
        self.certificates: list[dict[str, Any]] = []
        self.hosts: list[dict[str, Any]] = []
        self._next_id = 100

    def handler(self, request: httpx.Request) -> httpx.Response:
        path = request.url.path
        self.calls.append((request.method, path))
        if path.endswith("/hosts") and request.method == "GET":
            return httpx.Response(200, json={"hosts": [{"id": h["id"]} for h in self.hosts]})
        if path.endswith("/device_mapping"):
            which = int(path.split("/hosts/")[1].split("/")[0])
            found = next(h for h in self.hosts if h["id"] == which)
            return httpx.Response(200, json={"device_mapping": found.get("device_mapping") or []})
        if "/hosts/" in path and request.method == "GET":
            which = int(path.rsplit("/", 1)[-1])
            found = next(h for h in self.hosts if h["id"] == which)
            return httpx.Response(200, json={"host": {"mdm": {"profiles": found.get("profiles") or []}}})
        if path.endswith("/certificate_authorities"):
            return httpx.Response(200, json={"certificate_authorities": [{"id": 3, "name": "RMSCEP"}]})
        if path.endswith("/certificates") and request.method == "GET":
            return httpx.Response(200, json={"certificates": self.certificates})
        if path.endswith("/certificates") and request.method == "POST":
            body = json.loads(request.content)
            made = {
                "id": 27,
                "name": body["name"],
                "subject_name": body["subject_name"],
                "certificate_authority_id": body["certificate_authority_id"],
            }
            self.certificates.append(made)
            return httpx.Response(200, json=made)
        if "/certificates/" in path and request.method == "DELETE":
            gone = int(path.rsplit("/", 1)[-1])
            self.certificates = [c for c in self.certificates if c["id"] != gone]
            return httpx.Response(200, json={})
        if path == "/api/latest/fleet/teams" and request.method == "GET":
            return httpx.Response(200, json={"teams": [{"id": 7, "name": "rmscep"}]})
        if path.endswith("/software/titles"):
            return httpx.Response(200, json={"software_titles": list(self.titles)})
        if path.endswith("/software/app_store_apps"):
            body = json.loads(request.read())
            self._next_id += 1
            self.titles.append({"id": self._next_id, "app_store_app": {"app_store_id": body["app_store_id"]}})
            return httpx.Response(200, json={"software_title_id": self._next_id})
        if path.endswith("/configuration_profiles"):
            if request.method == "GET":
                return httpx.Response(200, json={"profiles": list(self.profiles)})
            # An upload the MDM keeps, so a second pass can see it is already there. Without
            # this the adapter is right to upload again: a profile that has gone missing must
            # be restored whatever we remember pushing.
            self.profiles.append({"name": "rmscep-policy", "profile_uuid": f"uuid-{len(self.profiles)}"})
            return httpx.Response(200, json={})
        if "/configuration_profiles/" in path and request.method == "DELETE":
            self.profiles.clear()
            return httpx.Response(200, json={})
        if "/app_store_app" in path or path.endswith("/setup_experience/software"):
            return httpx.Response(200, json={})
        return httpx.Response(200, json={})


def _mdm(fleet: _Fleet, monkeypatch: pytest.MonkeyPatch) -> FleetMdm:
    transport = httpx.MockTransport(fleet.handler)
    monkeypatch.setattr(httpx, "request", lambda m, u, **kw: httpx.Client(transport=transport).request(m, u, **kw))
    monkeypatch.setattr(httpx, "post", lambda u, **kw: httpx.Client(transport=transport).post(u, **kw))
    return FleetMdm("https://mdm.test", "token")


def test_the_policy_lands_before_anything_installs(monkeypatch: pytest.MonkeyPatch) -> None:
    """A permission grant only applies to an app that installs while it is already in force

    Land it late and the device comes up facing a permission wizard, with a certificate no app
    is allowed to see.
    """
    fleet = _Fleet()
    _mdm(fleet, monkeypatch).apply("rmscep", TEMPLATE)

    paths = [p for _, p in fleet.calls]
    profile = next(i for i, p in enumerate(paths) if p.endswith("/configuration_profiles"))
    install = next(i for i, p in enumerate(paths) if p.endswith("/software/app_store_apps"))
    assert profile < install, f"policy must precede installs, got {paths}"


def test_only_the_chosen_apps_install_at_enrolment(monkeypatch: pytest.MonkeyPatch) -> None:
    """The rest stay available on demand rather than lengthening the enrolment burst"""
    fleet = _Fleet()
    result = _mdm(fleet, monkeypatch).apply("rmscep", TEMPLATE)
    assert result["preinstall"] == ["com.example.one"]
    assert len(result["assigned"]) == 2


def test_an_unchanged_policy_is_not_rewritten(monkeypatch: pytest.MonkeyPatch) -> None:
    """Measured: a policy rewritten every pass never settles and nothing ever installs"""
    fleet = _Fleet()
    mdm = _mdm(fleet, monkeypatch)
    mdm.apply("rmscep", TEMPLATE)
    uploads_after_first = len([1 for m, p in fleet.calls if m == "POST" and p.endswith("/configuration_profiles")])
    mdm.apply("rmscep", TEMPLATE)
    uploads_after_second = len([1 for m, p in fleet.calls if m == "POST" and p.endswith("/configuration_profiles")])
    assert uploads_after_second == uploads_after_first, "the same policy must not be uploaded twice"


def test_force_reaches_a_host_that_just_joined(monkeypatch: pytest.MonkeyPatch) -> None:
    """A profile is delivered when the PROFILE changes, not when a host arrives"""
    fleet = _Fleet()
    mdm = _mdm(fleet, monkeypatch)
    mdm.apply("rmscep", TEMPLATE)
    before = len([1 for m, p in fleet.calls if m == "POST" and p.endswith("/configuration_profiles")])
    mdm.apply("rmscep", TEMPLATE, force_policy=True)
    after = len([1 for m, p in fleet.calls if m == "POST" and p.endswith("/configuration_profiles")])
    assert after == before + 1


def test_a_refusal_is_reported_not_swallowed(monkeypatch: pytest.MonkeyPatch) -> None:
    """Applying half a template is worse than applying none"""
    transport = httpx.MockTransport(lambda request: httpx.Response(403, text="nope"))
    monkeypatch.setattr(httpx, "request", lambda m, u, **kw: httpx.Client(transport=transport).request(m, u, **kw))
    with pytest.raises(FleetError):
        FleetMdm("https://mdm.test", "token").apply("rmscep", TEMPLATE)


def test_the_launcher_icon_is_a_valid_png() -> None:
    """Without one the web app is accepted and then never published, and every install says NOT_FOUND"""
    png = launcher_icon()
    assert png[:8] == b"\x89PNG\r\n\x1a\n"
    width = int.from_bytes(png[16:20], "big")
    height = int.from_bytes(png[20:24], "big")
    assert width == height == 512, "square and at least 512x512 is enforced"


def test_the_link_app_is_offered_alongside_the_others(monkeypatch: pytest.MonkeyPatch) -> None:
    """It is a browser shortcut, so it only works if the browser is installed too"""
    fleet = _Fleet()
    monkeypatch.setattr(FleetMdm, "ensure_link_app", lambda self, team, title, url: "com.google.enterprise.webapp.test")
    with_link = MdmTemplate(apps=TEMPLATE.apps, policy=TEMPLATE.policy, link_app=LinkApp("Deploy App", "https://x/"))
    result = _mdm(fleet, monkeypatch).apply("rmscep", with_link)
    assert "com.google.enterprise.webapp.test" in result["preinstall"]


def test_the_certificate_template_is_stated_before_anything_else(monkeypatch: pytest.MonkeyPatch) -> None:
    """Its subject carries the proof that the MDM assigned this device this callsign

    So it is configuration that gets reviewed and deployed, not something typed into a console.
    """
    fleet = _Fleet()
    with_cert = MdmTemplate(
        apps=TEMPLATE.apps,
        policy=TEMPLATE.policy,
        certificate=Certificate(name="rmscep", subject="CN=$VAR,OU=$OTHER", authority="RMSCEP"),
    )
    _mdm(fleet, monkeypatch).apply("rmscep", with_cert)
    paths = [p for _, p in fleet.calls]
    assert any(p.endswith("/certificates") for p in paths), "the template must be stated"
    cert = next(i for i, p in enumerate(paths) if p.endswith("/certificates"))
    install = next(i for i, p in enumerate(paths) if p.endswith("/software/app_store_apps"))
    assert cert < install


def test_an_unknown_authority_is_named_rather_than_guessed(monkeypatch: pytest.MonkeyPatch) -> None:
    """A template pointing at an authority that is not there would issue nothing, silently"""
    fleet = _Fleet()
    with_cert = MdmTemplate(
        apps=TEMPLATE.apps,
        policy=TEMPLATE.policy,
        certificate=Certificate(name="rmscep", subject="CN=$VAR", authority="NOT-THERE"),
    )
    with pytest.raises(FleetError, match="NOT-THERE"):
        _mdm(fleet, monkeypatch).apply("rmscep", with_cert)


def test_an_unchanged_certificate_template_is_left_alone(monkeypatch: pytest.MonkeyPatch) -> None:
    """Recreating it re-asks every device in the team, so it is not done for nothing"""
    fleet = _Fleet()
    with_cert = MdmTemplate(
        apps=TEMPLATE.apps,
        policy=TEMPLATE.policy,
        certificate=Certificate(name="rmscep", subject="CN=$VAR,OU=$OTHER", authority="RMSCEP"),
    )
    mdm = _mdm(fleet, monkeypatch)
    mdm.apply("rmscep", with_cert)
    before = len([1 for method, path in fleet.calls if path.endswith("/certificates") and method == "POST"])
    mdm.apply("rmscep", with_cert)
    after = len([1 for method, path in fleet.calls if path.endswith("/certificates") and method == "POST"])
    assert after == before, "an unchanged template must not be recreated"


def test_forcing_the_certificate_asks_again(monkeypatch: pytest.MonkeyPatch) -> None:
    """The ordinary recovery: a device enrols before anyone can name it, so the first ask fails

    Fleet never retries a failed certificate, and the template is what asks. Recreating it is the
    only way a host named after it enrolled ever gets one.
    """
    fleet = _Fleet()
    with_cert = MdmTemplate(
        apps=TEMPLATE.apps,
        policy=TEMPLATE.policy,
        certificate=Certificate(name="rmscep", subject="CN=$VAR,OU=$OTHER", authority="RMSCEP"),
    )
    mdm = _mdm(fleet, monkeypatch)
    mdm.apply("rmscep", with_cert)
    fleet.calls.clear()
    mdm.apply("rmscep", with_cert, force_certificate=True)

    assert any(method == "DELETE" and "/certificates/" in path for method, path in fleet.calls)
    assert any(method == "POST" and path.endswith("/certificates") for method, path in fleet.calls)
    assert len(fleet.certificates) == 1, "the template is replaced, not duplicated"
    assert fleet.certificates[0]["name"] == "rmscep", "the keystore alias has to stay the same"


def _host(host_id: int, status: str, named: bool) -> dict[str, Any]:
    return {
        "id": host_id,
        "profiles": [{"name": "rmscep", "status": status}],
        "device_mapping": [{"email": "OTTER1@CODE", "source": "mdm_idp_accounts"}] if named else [],
    }


def test_a_host_named_after_enrolment_is_waiting(monkeypatch: pytest.MonkeyPatch) -> None:
    """Named, and still refused: asking again would now work"""
    fleet = _Fleet()
    fleet.hosts = [_host(1, "failed", named=True)]
    assert _mdm(fleet, monkeypatch).hosts_awaiting_certificate(1, "rmscep") == [1]


def test_a_host_nobody_has_named_is_not_waiting(monkeypatch: pytest.MonkeyPatch) -> None:
    """Asking again changes nothing until somebody names it, and re-asking is not free"""
    fleet = _Fleet()
    fleet.hosts = [_host(2, "failed", named=False)]
    assert _mdm(fleet, monkeypatch).hosts_awaiting_certificate(1, "rmscep") == []


def test_a_host_that_already_has_its_certificate_is_not_waiting(monkeypatch: pytest.MonkeyPatch) -> None:
    """Otherwise every pass would re-ask the whole group forever"""
    fleet = _Fleet()
    fleet.hosts = [_host(3, "verified", named=True)]
    assert _mdm(fleet, monkeypatch).hosts_awaiting_certificate(1, "rmscep") == []
