"""The template document

What a deployment installs is data, not code. These tests pin that the responder stays ignorant
of it and that a malformed document is refused before it can reach an MDM.
"""

import json
from pathlib import Path

import pytest

from rmscep.mdmtemplate import TemplateError, load

GOOD = {
    "apps": [
        {"package": "com.example.one", "preinstall": True},
        {
            "package": "com.example.two",
            "preinstall": False,
            "config": {"AutoSelectCertificateForUrls": ['{"pattern":"{mtls_url}","filter":{}}']},
        },
    ],
    "link_app": {"title": "Deploy App", "url": "{mtls_url}/"},
    "policy": {
        "choosePrivateKeyRules": [{"urlPattern": "{mtls_url}", "privateKeyAlias": "{key_alias}"}],
        "defaultPermissionPolicy": "GRANT",
    },
}


def _write(tmp_path: Path, body: object) -> Path:
    path = tmp_path / "template.json"
    path.write_text(json.dumps(body), encoding="utf-8")
    return path


def test_placeholders_are_filled_at_every_depth(tmp_path: Path) -> None:
    """The document is written once and used against whatever deployment it is pointed at"""
    template = load(_write(tmp_path, GOOD), domain="example.fi", key_alias="rmscep")

    assert template.preinstall_packages == ("com.example.one",)
    inside_a_list = template.apps[1].config["AutoSelectCertificateForUrls"][0]
    assert json.loads(inside_a_list)["pattern"] == "https://mtls.example.fi"
    assert template.policy["choosePrivateKeyRules"][0]["urlPattern"] == "https://mtls.example.fi"
    assert template.policy["choosePrivateKeyRules"][0]["privateKeyAlias"] == "rmscep"
    assert template.link_app is not None
    assert template.link_app.url == "https://mtls.example.fi/"


@pytest.mark.parametrize(
    ("body", "because"),
    [
        ({"apps": []}, "a template that installs nothing is a mistake, not a choice"),
        ({"apps": [{"preinstall": True}]}, "an app with no package cannot be acted on"),
        ({"apps": [{"package": "x", "config": []}]}, "config must be an object"),
        ({"apps": [{"package": "x"}], "policy": []}, "policy must be an object"),
        ({"apps": [{"package": "x"}], "link_app": {"title": "t"}}, "a link with no url is useless"),
        ([], "the document must be an object"),
    ],
)
def test_a_malformed_document_is_refused(tmp_path: Path, body: object, because: str) -> None:
    """A half applied template is worse than none: apps install at enrolment only, so a device
    that joined against a broken one has to be enrolled again, and its callsign is spent."""
    with pytest.raises(TemplateError):
        load(_write(tmp_path, body), domain="example.fi", key_alias="rmscep")


def test_a_missing_file_is_refused(tmp_path: Path) -> None:
    with pytest.raises(TemplateError):
        load(tmp_path / "nope.json", domain="example.fi", key_alias="rmscep")


def test_not_json_is_refused(tmp_path: Path) -> None:
    path = tmp_path / "template.json"
    path.write_text("this is not json", encoding="utf-8")
    with pytest.raises(TemplateError):
        load(path, domain="example.fi", key_alias="rmscep")
