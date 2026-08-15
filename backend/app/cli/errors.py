from __future__ import annotations

import logging

logger = logging.getLogger(__name__)


def report_cli_error(message: str) -> None:
    logger.error("CLI operation failed: %s", message)
