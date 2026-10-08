"""The report for an MDM we have no driver for

What is under test is that the report says the things a person cannot work out for themselves and
would get wrong: the subject convention, the order of operations, and the two rules that are only
learned by losing an afternoon to them.
"""

from rmscep.mdm import ManualMdm
from rmscep.mdmtemplate import App, Certificate, LinkApp, MdmTemplate

URL = "https://deployment.test/scep"


def _a_template() -> MdmTemplate:
    return MdmTemplate(
        apps=(
            App(package="com.example.one", preinstall=True, config={"Setting": "value"}),
            App(package="com.example.two", preinstall=False),
        ),
        policy={"choosePrivateKeyRules": [{"privateKeyAlias": "rmscep", "urlPattern": "https://mtls.x.*"}]},
        link_app=LinkApp(title="Deploy App", url="https://mtls.deployment.test/"),
        certificate=Certificate(
            name="rmscep",
            subject="CN=$SOME_MDM_VARIABLE,OU=$SOME_MDM_VARIABLE_TOO",
            authority="RMSCEP",
        ),
    )


def test_it_states_the_subject_convention_rather_than_one_mdm_s_syntax() -> None:
    """Any MDM can satisfy the contract; none of them spell the variables the same way"""
    report = ManualMdm(URL).describe("a-group", _a_template())
    assert "<callsign>@<approval code>" in report
    assert "common name" in report
    assert "Yours will differ" in report


def test_it_warns_that_a_subject_which_does_not_resolve_is_silent() -> None:
    """The failure that cost a day: no request is sent, so our logs say nothing at all"""
    report = ManualMdm(URL).describe("a-group", _a_template())
    assert "no request at all" in report


def test_it_warns_that_apps_install_only_at_enrolment() -> None:
    """Otherwise an operator adds an app, sees nothing happen, and blames the template"""
    report = ManualMdm(URL).describe("a-group", _a_template())
    assert "ENROLMENT" in report


def test_it_carries_the_scep_url_and_points_at_the_challenge_without_printing_it() -> None:
    """A report is not a place to copy a credential to, even a deliberately weak one"""
    report = ManualMdm(URL).describe("a-group", _a_template())
    assert URL in report
    assert "RMSCEP_CHALLENGE" in report


def test_it_lists_the_apps_and_their_configuration() -> None:
    """Managed configuration is half of what makes a certificate usable, so it cannot be implied"""
    report = ManualMdm(URL).describe("a-group", _a_template())
    assert "com.example.one (at enrolment)" in report
    assert "com.example.two (available on demand)" in report
    assert "config Setting" in report
    assert "Deploy App" in report


def test_a_template_with_no_certificate_says_so_instead_of_omitting_it() -> None:
    """Silence would read as 'nothing to do' when it means the deployment is misconfigured"""
    bare = MdmTemplate(apps=(), policy={})
    report = ManualMdm(URL).describe("a-group", bare)
    assert "No certificate template" in report


def test_it_never_claims_to_have_applied_anything() -> None:
    """It changes nothing, and an operator acting as though it did would ship a broken deployment"""
    report = ManualMdm(URL).describe("a-group", _a_template())
    assert report.startswith("Nothing was applied")
