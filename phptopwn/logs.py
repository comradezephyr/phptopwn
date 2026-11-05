"""Logging plumbing: text formatter plus optional one-object-per-line JSON."""
from __future__ import annotations

import json
import logging
import time


class JsonFormatter(logging.Formatter):
    """Emit each record as one JSON object, mirroring the text format fields."""

    def format(self, record: logging.LogRecord) -> str:
        stamp = time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime(record.created))
        millis = f"{(record.created % 1) * 1000:03.0f}"
        payload: dict[str, str | float] = {
            "timestamp": f"{stamp}.{millis}",
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }
        if record.exc_info:
            payload["exception"] = self.formatException(record.exc_info)
        return json.dumps(payload, ensure_ascii=False)
