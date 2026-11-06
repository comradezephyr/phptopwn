"""Shared runtime state: sensor wiring, source guards, background sweeps."""
from __future__ import annotations

import asyncio
import logging
import time
from collections import OrderedDict, deque

from .alerts import AlertHub
from .capture import RequestCapture
from .config import Config
from .fleet import FleetForwarder
from .storage import ArtifactStore, retention_sweep, utc_now

LOG = logging.getLogger("phptopwn.sensor")

_MAX_TRACKED_IPS = 8192
_MAX_TRACKED_SIGNALS = 256


class SourceGuard:
    """Per-source-IP in-memory limits: concurrency and rolling-minute rate."""

    def __init__(self, max_concurrent: int, rate_per_minute: int) -> None:
        self.max_concurrent = max_concurrent
        self.rate_per_minute = rate_per_minute
        self._inflight: dict[str, int] = {}
        self._recent: OrderedDict[str, deque[float]] = OrderedDict()
        self._capacity = 16384

    def acquire(self, ip: str) -> str | None:
        """Count one request from this source; return a rejection reason or None."""
        now = time.monotonic()
        if self.rate_per_minute:
            window = self._recent.get(ip)
            if window is None:
                window = deque()
                self._recent[ip] = window
                self._recent.move_to_end(ip)
                while len(self._recent) > self._capacity:
                    self._recent.popitem(last=False)
            while window and now - window[0] > 60.0:
                window.popleft()
            window.append(now)
            if len(window) > self.rate_per_minute:
                return "rate_limited"
        if self.max_concurrent:
            active = self._inflight.get(ip, 0)
            if active >= self.max_concurrent:
                return "concurrent_limit"
            self._inflight[ip] = active + 1
        return None

    def release(self, ip: str) -> None:
        if not self.max_concurrent:
            return
        active = self._inflight.get(ip)
        if active is None:
            return
        if active <= 1:
            self._inflight.pop(ip, None)
        else:
            self._inflight[ip] = active - 1


class Metrics:
    """Plain counter state feeding /healthz JSON and /metrics."""

    def __init__(self) -> None:
        self.counters: dict[str, int] = {
            "requests": 0,
            "exploits": 0,
            "benign": 0,
            "errors": 0,
            "alerts_sent": 0,
            "alerts_failed": 0,
            "alerts_metered": 0,
            "alerts_overflow": 0,
            "fleet_events_shipped": 0,
            "fleet_bytes_shipped": 0,
            "fleet_event_skips": 0,
        }
        self.signatures: dict[str, int] = {}
        self.ip_totals: OrderedDict[str, int] = OrderedDict()
        self.ip_window: OrderedDict[str, deque[float]] = OrderedDict()
        self.body_bytes: int = 0
        self.last_exploit_at: str | None = None
        self.started_at = utc_now()
        self.start_time = time.monotonic()

    def uptime(self) -> float:
        return time.monotonic() - self.start_time

    def observe_capture(self, capture: RequestCapture) -> None:
        self.counters["requests"] += 1
        self.body_bytes += capture.body_size
        analysis = capture.analysis
        if analysis is not None and analysis.is_exploit:
            self.counters["exploits"] += 1
            self.last_exploit_at = capture.timestamp
        else:
            self.counters["benign"] += 1
        if analysis is not None:
            for signal in analysis.signals:
                self.signatures[signal.id] = self.signatures.get(signal.id, 0) + 1
                while len(self.signatures) > _MAX_TRACKED_SIGNALS:
                    self.signatures.pop(next(iter(self.signatures)))
        self._touch_ip(capture.client_ip)

    def observe_guard(self, kind: str, ip: str) -> None:
        self.counters[kind] = self.counters.get(kind, 0) + 1
        self.counters["requests"] += 1
        self._touch_ip(ip)

    def _touch_ip(self, ip: str) -> None:
        if not ip:
            return
        self.ip_totals[ip] = self.ip_totals.get(ip, 0) + 1
        self.ip_totals.move_to_end(ip)
        while len(self.ip_totals) > _MAX_TRACKED_IPS:
            self.ip_totals.popitem(last=False)
        window = self.ip_window.get(ip)
        if window is None:
            window = deque(maxlen=512)
            self.ip_window[ip] = window
            while len(self.ip_window) > _MAX_TRACKED_IPS:
                self.ip_window.popitem(last=False)
        now = time.monotonic()
        while window and now - window[0] > 60.0:
            window.popleft()
        window.append(now)

    def request_rate(self) -> float:
        now = time.monotonic()
        active = 0
        for window in list(self.ip_window.values()):
            for stamp in window:
                if now - stamp <= 60.0:
                    active += 1
        return active / 60.0

    def top_sources(self, limit: int = 10) -> list[dict[str, int | str]]:
        items = sorted(self.ip_totals.items(), key=lambda kv: kv[1], reverse=True)
        return [{"ip": ip, "requests": count} for ip, count in items[:limit]]

    def snapshot(self) -> dict[str, object]:
        return {
            "started_at": self.started_at,
            "uptime_seconds": round(self.uptime(), 1),
            "counters": dict(self.counters),
            "signatures": dict(sorted(self.signatures.items(), key=lambda kv: -kv[1])[:50]),
            "top_sources": self.top_sources(),
            "request_rate_per_minute": round(self.request_rate(), 2),
            "body_bytes_observed": self.body_bytes,
            "last_exploit_at": self.last_exploit_at,
        }


class Sensor:
    """Owns config-backed state: the store, source guards and shared metrics."""

    def __init__(self, cfg: Config) -> None:
        self.cfg = cfg
        self.log = logging.getLogger("phptopwn.sensor")
        self.store = ArtifactStore(cfg)
        self.metrics = Metrics()
        self.guard = SourceGuard(cfg.limits.max_concurrent_per_ip, cfg.limits.rate_limit_per_minute)
        self.alerts = AlertHub(cfg, self.metrics)
        self.fleet: FleetForwarder | None = None
        if cfg.fleet.enabled:
            self.fleet = FleetForwarder(cfg, self.metrics)
        self._tasks: list[asyncio.Task[None]] = []

    def open(self) -> None:
        self.store.open()
        if self.fleet is not None:
            self.store.set_event_sink(self.fleet.sink.write)

    def start_maintenance(self) -> None:
        self._tasks.append(asyncio.create_task(retention_loop(self.cfg)))
        if self.fleet is not None:
            self.fleet.start()

    async def shutdown(self) -> None:
        for task in self._tasks:
            task.cancel()
        if self._tasks:
            await asyncio.gather(*self._tasks, return_exceptions=True)
        self._tasks.clear()
        await self.alerts.close()
        if self.fleet is not None:
            self.fleet.stop()


async def retention_loop(cfg: Config) -> None:
    """Periodically apply capture-dir and log-dir retention on a worker thread."""
    while True:
        await asyncio.sleep(cfg.retention.sweep_interval_seconds)
        try:
            stats = await asyncio.to_thread(
                retention_sweep,
                cfg.retention,
                cfg.storage.capture_dir,
                cfg.storage.log_dir,
            )
            if any(stats.values()):
                LOG.info("retention sweep: %s", stats)
        except Exception:  # retention must never take the sensor down
            LOG.exception("retention sweep failed")
