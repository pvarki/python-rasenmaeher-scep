"""What to configure, for an MDM we have no driver for

Enrolling devices needs nothing product specific: the contract is RFC 8894 plus a convention about
the certificate subject, and any MDM that can act as a SCEP client satisfies it. Only pushing apps
and policy needs an API, and that part is per MDM by nature and always will be.

So rather than pretend a driver exists, this says what a person should configure. It is the honest
shape of "works with any MDM": the enrolment half is automatic everywhere, and the rest is a page
of instructions rather than nothing at all.
"""

import json
from dataclasses import dataclass

from ..mdmtemplate import MdmTemplate


@dataclass(frozen=True)
class ManualMdm:
    """A report, not a driver: it changes nothing and talks to nothing"""

    scep_url: str

    def describe(self, group: str, template: MdmTemplate) -> str:
        """Everything a person needs to type into an MDM console, in the order to type it"""
        lines = [
            "Nothing was applied. This is what to configure by hand.",
            "",
            f"Devices of this deployment belong in the group {group!r}. Everything below is set on",
            "that group, not on the whole estate.",
            "",
            "1. A SCEP certificate authority",
            f"     URL       {self.scep_url}",
            "     challenge the value of RMSCEP_CHALLENGE",
            "",
            "   Most MDMs fetch GetCACert when the CA is saved, so a wrong URL fails immediately.",
            "   That makes saving it the cheapest proof the responder is reachable at all.",
            "",
        ]
        lines += self._certificate_lines(template)
        lines += self._policy_lines(template)
        lines += self._app_lines(template)
        lines += [
            "Two things to know before you start:",
            "",
            "  Apps install at ENROLMENT and at no other time on managed Android. A device that has",
            "  already joined will not pick up anything added afterwards; it has to enrol again.",
            "",
            "  Nothing here can check itself. Run `rmscep selftest` against a callsign planned for",
            "  the purpose to prove the responder, then configure the MDM knowing that half is good.",
        ]
        return "\n".join(lines)

    def _certificate_lines(self, template: MdmTemplate) -> list[str]:
        """The part that actually matters, and the part every MDM words differently"""
        if not template.certificate:
            return ["2. No certificate template is stated for this deployment.", ""]
        return [
            "2. A certificate template issued by that authority",
            f"     name    {template.certificate.name}",
            f"     subject {template.certificate.subject}",
            "",
            "   The subject is the contract. RASENMAEHER needs the callsign as the common name, and",
            "   the string '<callsign>@<approval code>' in any other attribute, which is what proves",
            "   the MDM was told to give this device that callsign rather than a caller guessing it.",
            "",
            "   The variables above are written in one MDM's syntax. Yours will differ: what has to",
            "   be true is that the MDM can put an operator-set, per-device string into the subject,",
            "   and that you set it BEFORE the device enrols. A subject that does not resolve sends",
            "   no request at all, so nothing reaches our logs and only the MDM knows why.",
            "",
            "   The name becomes the keystore alias on the device. A second key will not install",
            f"   over an existing {template.certificate.name!r}, so keep it stable.",
            "",
        ]

    @staticmethod
    def _policy_lines(template: MdmTemplate) -> list[str]:
        """Android Management API, so it carries to any Android EMM built on it and nowhere else"""
        if not template.policy:
            return []
        body = json.dumps(template.policy, indent=2, sort_keys=True)
        return [
            "3. A device policy",
            "",
            *[f"     {line}" for line in body.splitlines()],
            "",
            "   These are Android Management API fields, so they carry to any Android EMM built on",
            "   it. They mean nothing to an MDM that is not, and nothing at all to iOS.",
            "",
            "   choosePrivateKeyRules says which key an app may use; the browser still decides",
            "   whether to send one. Both halves are needed, and a urlPattern is matched against the",
            "   whole URL, which carries a path and a port.",
            "",
        ]

    @staticmethod
    def _app_lines(template: MdmTemplate) -> list[str]:
        """Apps and the launcher link, which is a browser shortcut and needs the browser"""
        lines = ["4. Applications"]
        for app in template.apps:
            when = "at enrolment" if app.preinstall else "available on demand"
            lines.append(f"     {app.package} ({when})")
            for key, value in sorted(app.config.items()):
                lines.append(f"       config {key} = {json.dumps(value)}")
        if template.link_app:
            lines += [
                f"     a web app {template.link_app.title!r} -> {template.link_app.url}",
                "       needs an icon of at least 512x512 or it is never published",
            ]
        lines.append("")
        return lines
