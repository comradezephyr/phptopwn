"""Structured JSON log formatting and logging bootstrap."""
from __future__ import annotations

import json
import logging
import sys

from conftest import make_cfg

from phptopwn.logs import JsonFormatter
from phptopwn.server import setup_logging


def _record(level=logging.WARNING, msg="request %s handled", args=("abc",), exc_info=None):
    return logging.LogRecord(
        name="phptopwn.mw", level=level, pathname=__file__, lineno=1,
        msg=msg, args=args, exc_info=exc_info,
    )


def test_json_formatter_line_shape():
    formatter = JsonFormatter()
    payload = json.loads(formatter.format(_record()))
    assert payload["level"] == "WARNING"
    assert payload["logger"] == "phptopwn.mw"
    assert payload["message"] == "request abc handled"
    stamp = payload["timestamp"]
    assert stamp.endswith("Z") and "T" in stamp and stamp.count(".") == 1


def test_json_formatter_includes_exception():
    formatter = JsonFormatter()
    try:
        raise ValueError("boom")
    except ValueError:
        payload = None
        record = _record(level=logging.ERROR, msg="failed", args=(), exc_info=sys.exc_info())
    payload = json.loads(formatter.format(record))
    assert "ValueError" in payload["exception"] and "boom" in payload["exception"]


def test_setup_logging_json_mode_default():
    root = logging.getLogger()
    saved = (list(root.handlers), root.level)
    try:
        setup_logging(make_cfg(LOG_LEVEL="warning"))
        assert len(root.handlers) == 1
        assert isinstance(root.handlers[0].formatter, JsonFormatter)
        assert root.level == logging.WARNING
    finally:
        root.handlers = saved[0]
        root.setLevel(saved[1])


def test_setup_logging_text_mode():
    root = logging.getLogger()
    saved = (list(root.handlers), root.level)
    try:
        setup_logging(make_cfg(LOG_JSON="false"))
        assert len(root.handlers) == 1
        formatter = root.handlers[0].formatter
        text = formatter.format(_record())
        assert isinstance(text, str) and "WARNING" in text.split()
    finally:
        root.handlers = saved[0]
        root.setLevel(saved[1])
