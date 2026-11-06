"""Webhook alerting: severity-gated, per-IP metered, never request-blocking."""
from __future__ import annotations

import asyncio
import logging
import time
from collections import OrderedDict
from typing import TYPE_CHECKING

import httpx

from .capture import SEVERITY_RANK, RequestCapture
from .config import Config

if TYPE_CHECKING:
    from .runtime import Metrics

LOG = logging.getLogger("phptopwn.alerts")

_COOLDOWN_CAPACITY = 16384
_MAX_IOC_HINTS = 8
_MAX_SIGNAL_IDS = 8


class AlertHub:
    """Post exploit alerts to the configured webhook without stalling the decoy."""

    def __init__(self, cfg: Config, metrics: Metrics) -> None:
        self.cfg = cfg
        self.metrics = metrics
        self.webhook_url = cfg.alerts.webhook_url
        self.min_severity = SEVERITY_RANK.get(cfg.alerts.min_severity, 0)
        self.cooldown_seconds = cfg.alerts.cooldown_seconds
        self.max_inflight = cfg.alerts.max_inflight
        self._cooldown: OrderedDict[str, float] = OrderedDict()
        self._inflight = 0
        self._client: httpx.AsyncClient | None = None
        self._tasks: set[asyncio.Task[None]] = set()

    def maybe_dispatch(self, capture: RequestCapture) -> None:
        """Schedule one alert task for an analyzed capture if policy allows."""
        analysis = capture.analysis
        if not self.webhook_url or analysis is None or not analysis.is_exploit:
            return
        if SEVERITY_RANK.get(analysis.severity, 0) < self.min_severity:
            return
        if not self._pass_meter(capture.client_ip):
            return
        if self._inflight >= self.max_inflight:
            self.metrics.counters["alerts_overflow"] += 1
            return
        self._inflight += 1
        try:
            self._tracked(capture)
        except RuntimeError:  # pragma: no cover - defensive; callers are async
            self._inflight -= 1
            return

    def _tracked(self, capture: RequestCapture) -> asyncio.Task[None]:
        task = asyncio.get_running_loop().create_task(self._deliver(capture))
        self._tasks.add(task)
        task.add_done_callback(self._tasks.discard)
        return task

    def _pass_meter(self, ip: str) -> bool:
        """Return True when the source IP may raise a new alert now.

        The window opens only when an alert is dispatched; hits arriving while
        it is open are counted but never refresh it, so an ongoing attack
        keeps re-alerting once per cooldown period.
        """
        now = time.monotonic()
        last = self._cooldown.get(ip)
        if last is not None and now - last < self.cooldown_seconds:
            self.metrics.counters["alerts_metered"] += 1
            return False
        self._cooldown[ip] = now
        self._cooldown.move_to_end(ip)
        while len(self._cooldown) > _COOLDOWN_CAPACITY:
            self._cooldown.popitem(last=False)
        return True

    async def _deliver(self, capture: RequestCapture) -> None:
        payload = {
            "sensor": "phptopwn",
            "request_id": capture.request_id,
            "timestamp": capture.timestamp,
            "client_ip": capture.client_ip,
            "method": capture.method,
            "path": capture.path,
            "severity": capture.analysis.severity if capture.analysis else "info",
            "cves": capture.analysis.cves if capture.analysis else [],
            "signals": [signal.id for signal in (capture.analysis.signals if capture.analysis else [])][
                :_MAX_SIGNAL_IDS
            ],
            "iocs": capture.analysis.iocs if capture.analysis else {},
        }
        try:
            if self._client is None:
                self._client = httpx.AsyncClient(trust_env=False, timeout=self.cfg.alerts.timeout_seconds)
            response = await self._client.post(self.webhook_url, json=payload)
            if 200 <= response.status_code < 300:
                self.metrics.counters["alerts_sent"] += 1
            else:
                self.metrics.counters["alerts_failed"] += 1
                LOG.warning(
                    "webhook returned HTTP %s for %s", response.status_code, capture.request_id
                )
        except Exception:
            self.metrics.counters["alerts_failed"] += 1
            LOG.warning("webhook delivery failed for %s", capture.request_id, exc_info=True)
        finally:
            self._inflight -= 1

    async def close(self) -> None:
        """Finish pending deliveries, drop task references and close the client."""
        if self._tasks:
            pending = list(self._tasks)
            await asyncio.gather(*pending, return_exceptions=True)
            self._tasks.clear()
        client, self._client = self._client, None
        if client is not None:
            await client.aclose()
