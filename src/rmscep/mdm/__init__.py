"""Saying what a deployment needs to whichever MDM a unit runs

The responder itself never talks to an MDM: it answers SCEP and nothing else. This package is
used by the `mdm` CLI commands, which an operator runs when a deployment is set up or changes.
Keeping it out of the request path is deliberate -- an internet facing parser has no business
holding an MDM's API token.
"""

from .fleet import FleetError, FleetMdm

__all__ = ["FleetError", "FleetMdm"]
