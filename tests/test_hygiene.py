"""Two properties that are easy to lose and expensive to notice

Neither is about a single function. They are about the shape of the whole package, so they live
apart from the behaviour tests.
"""

import logging
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from rmscep import config

from .test_scep import CHALLENGE, build_pkcs_req
from .test_web import ISSUED_CALLSIGN, client  # noqa: F401  -- the fixture is used by name

SRC = Path(__file__).resolve().parent.parent / "src" / "rmscep"

#: Product knowledge belongs in the product integrations, never here. The responder speaks SCEP to
#: an MDM and HTTP to RASENMAEHER, and that is the whole of what it knows.
#:
#: An MDM vendor's name is deliberately NOT on this list. Naming the client implementation that
#: makes a protocol workaround necessary is what stops the next person deleting it; the rule is
#: about knowing a product's packages, config keys and formats, which is coupling.
FORBIDDEN = ("atakmap", "element", "vector", "tak_zips", "enterpriseConfiguration", "_atak.zip")


def test_no_product_names_in_the_source() -> None:
    """The responder must stay ignorant of what any product's clients are called"""
    offences = []
    for path in SRC.rglob("*.py"):
        body = path.read_text(encoding="utf-8").lower()
        for needle in FORBIDDEN:
            if needle.lower() in body:
                offences.append(f"{path.relative_to(SRC)} mentions {needle}")
    assert not offences, "; ".join(offences)


def test_the_challenge_is_never_logged(
    client: TestClient,  # noqa: F811
    tmp_path: Path,
    caplog: pytest.LogCaptureFixture,
) -> None:
    """It is not a secret, but it has no business in a log either

    Logs travel further than the configuration does, and a challenge in one is an invitation to
    anyone reading them to try the endpoint.
    """
    ra = __import__("rmscep.scep", fromlist=["RaIdentity"]).RaIdentity.load_or_create(tmp_path / "ra")
    with caplog.at_level(logging.DEBUG):
        # once accepted, once refused: the refusal path is the likelier place to leak it
        client.post(
            "/scep",
            params={"operation": "PKIOperation"},
            content=build_pkcs_req(ra, ISSUED_CALLSIGN),
        )
        client.post(
            "/scep",
            params={"operation": "PKIOperation"},
            content=build_pkcs_req(ra, ISSUED_CALLSIGN, challenge="a-wrong-one-0987"),
        )
    logged = "\n".join(record.getMessage() for record in caplog.records)
    assert CHALLENGE not in logged, "the configured challenge reached the log"
    assert "a-wrong-one-0987" not in logged, "the challenge a caller sent reached the log"
    assert config.CHALLENGE not in logged
