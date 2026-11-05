"""Internal listener: JSON health status and counters.

This app is separate from the decoy surface and never passes through the
telemetry middleware, so probe hits are not logged as attacks and do not
pollute the exploit record stream.
"""
from __future__ import annotations

import logging
from typing import Any

from starlette.applications import Starlette
from starlette.responses import JSONResponse
from starlette.routing import Route

from .runtime import Sensor

LOG = logging.getLogger("phptopwn.internal")


def build_internal_app(sensor: Sensor) -> Starlette:
    async def healthz(request: Any) -> JSONResponse:
        snapshot = sensor.metrics.snapshot()
        return JSONResponse(
            {
                "status": "ok",
                "version": _version(),
                "uptime_seconds": snapshot["uptime_seconds"],
                "started_at": snapshot["started_at"],
                "counters": snapshot["counters"],
                "request_rate_per_minute": snapshot["request_rate_per_minute"],
                "last_exploit_at": snapshot["last_exploit_at"],
            }
        )

    return Starlette(routes=[Route("/healthz", healthz, methods=["GET"])])


def _version() -> str:
    from . import __version__

    return __version__
