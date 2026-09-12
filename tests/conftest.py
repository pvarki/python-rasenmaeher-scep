"""pytest automagics"""

import logging
import os

from libpvarki.logging import add_trace_and_audit, init_logging

# The service default is ECS JSON, which is unreadable when a test fails
os.environ["LOG_CONSOLE_FORMATTER"] = "local"
add_trace_and_audit()
init_logging(logging.DEBUG)

LOGGER = logging.getLogger(__name__)
