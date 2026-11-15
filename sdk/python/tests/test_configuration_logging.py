"""Logging defaults must never enable HTTP wire dumps that expose credentials."""

import logging
from http.client import HTTPConnection

from cipherrun_client.configuration import Configuration


def test_debug_mode_does_not_enable_http_wire_logging():
    package_logger = logging.getLogger("cipherrun_client")
    urllib3_logger = logging.getLogger("urllib3")
    original_debuglevel = HTTPConnection.debuglevel
    original_package_level = package_logger.level
    original_urllib3_level = urllib3_logger.level
    try:
        HTTPConnection.debuglevel = 0

        Configuration(debug=True)

        assert HTTPConnection.debuglevel == 0
        assert package_logger.level == logging.DEBUG
        assert urllib3_logger.level == logging.WARNING
    finally:
        HTTPConnection.debuglevel = original_debuglevel
        package_logger.setLevel(original_package_level)
        urllib3_logger.setLevel(original_urllib3_level)
