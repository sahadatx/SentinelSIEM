from __future__ import annotations

import json
import logging

from app.core.logging import JsonFormatter


def test_log_formatter_does_not_emit_sensitive_payload_fields() -> None:
    record = logging.LogRecord(
        name="test",
        level=logging.INFO,
        pathname=__file__,
        lineno=1,
        msg="authentication event",
        args=(),
        exc_info=None,
    )
    output = JsonFormatter().format(record)
    payload = json.loads(output)

    assert "password" not in payload
    assert "token" not in payload
    assert payload["message"] == "authentication event"
