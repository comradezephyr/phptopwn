"""Internal listener: JSON health status plus Prometheus metrics exposition.

This app is separate from the decoy surface and never passes through the
telemetry middleware, so probe hits are not logged as attacks and do not
pollute the exploit record stream.
"""
from __future__ import annotations

import logging
from datetime import datetime
from typing import Any

from prometheus_client import CONTENT_TYPE_LATEST, CollectorRegistry, generate_latest
from prometheus_client.core import CounterMetricFamily, GaugeMetricFamily
from starlette.applications import Starlette
from starlette.responses import JSONResponse, Response
from starlette.routing import Route

from .runtime import Metrics, Sensor

LOG = logging.getLogger("phptopwn.internal")

_GUARD_REASONS = ("rate_limited", "concurrent_limit", "header_flood")
_ALERT_OUTCOMES = ("sent", "failed", "metered", "overflow")


class SensorCollector:
    """Expose the bounded in-memory stats; no unbounded label cardinality."""

    def __init__(self, metrics: Metrics) -> None:
        self.metrics = metrics

    def describe(self):
        return []

    def collect(self):
        m = self.metrics
        uptime = GaugeMetricFamily(
            "phptopwn_uptime_seconds", "Seconds since the sensor started."
        )
        uptime.add_metric([], round(m.uptime(), 3))
        yield uptime

        requests = CounterMetricFamily(
            "phptopwn_requests", "Requests observed by the sensor.", labels=["kind"]
        )
        requests.add_metric(["exploit"], m.counters["exploits"])
        requests.add_metric(["benign"], m.counters["benign"])
        yield requests

        guard = CounterMetricFamily(
            "phptopwn_guard_rejections", "Requests refused by the source guard.", labels=["reason"]
        )
        for reason in _GUARD_REASONS:
            guard.add_metric([reason], m.counters.get(reason, 0))
        yield guard

        signatures = CounterMetricFamily(
            "phptopwn_signature_hits", "Detection signal hits by signal id.", labels=["signature"]
        )
        for signal_id, count in sorted(m.signatures.items()):
            signatures.add_metric([signal_id], count)
        yield signatures

        alerts = CounterMetricFamily(
            "phptopwn_alerts", "Webhook alert dispatch outcomes.", labels=["outcome"]
        )
        for outcome in _ALERT_OUTCOMES:
            alerts.add_metric([outcome], m.counters.get(f"alerts_{outcome}", 0))
        yield alerts

        body = CounterMetricFamily("phptopwn_body_bytes", "Request body bytes observed.")
        body.add_metric([], m.body_bytes)
        yield body

        rate = GaugeMetricFamily("phptopwn_request_rate_per_minute", "Rolling request rate.")
        rate.add_metric([], round(m.request_rate(), 4))
        yield rate

        sources = CounterMetricFamily(
            "phptopwn_top_client", "Rolling totals for the busiest sources.", labels=["ip"]
        )
        for source in m.top_sources(10):
            sources.add_metric([str(source["ip"])], int(source["requests"]))
        yield sources

        last = GaugeMetricFamily(
            "phptopwn_last_exploit_at_seconds", "Unix timestamp of the last classified exploit."
        )
        last.add_metric([], self._unix(m.last_exploit_at))
        yield last

    @staticmethod
    def _unix(stamp: str | None) -> float:
        if not stamp:
            return 0.0
        try:
            return datetime.fromisoformat(stamp).timestamp()
        except ValueError:
            return 0.0


def build_internal_app(sensor: Sensor) -> Starlette:
    registry = CollectorRegistry()
    registry.register(SensorCollector(sensor.metrics))

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

    async def prom_metrics(request: Any) -> Response:
        return Response(generate_latest(registry), media_type=CONTENT_TYPE_LATEST)

    return Starlette(
        routes=[
            Route("/healthz", healthz, methods=["GET"]),
            Route("/metrics", prom_metrics, methods=["GET"]),
        ]
    )


def _version() -> str:
    from . import __version__

    return __version__
