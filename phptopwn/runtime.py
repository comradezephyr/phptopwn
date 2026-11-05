"""Shared runtime state for one running sensor instance."""
from __future__ import annotations

import time
from collections import OrderedDict, deque
from typing import Any

from .config import Config
from .storage import ArtifactStore, utc_now

_MAX_TRACKED_IPS = 8192
_MAX_TRACKED_SIGNALS = 256


class Metrics:
    """Plain counter state feeding /healthz JSON and, later, /metrics."""

    def __init__(self) -> None:
        self.counters: dict[str, int] = {
            "requests": 0,
            "exploits": 0,
            "benign": 0,
            "errors": 0,
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

    def observe_capture(self, capture: Any) -> None:
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

    def snapshot(self) -> dict[str, Any]:
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
    """Owns config-backed state: the store and shared metrics."""

    def __init__(self, cfg: Config) -> None:
        self.cfg = cfg
        self.log = None  # replaced by the logging setup in server.py
        self.store = ArtifactStore(cfg)
        self.metrics = Metrics()
        self.source = "built-in defaults"

    def open(self) -> None:
        self.store.open()

    def shutdown(self) -> None:
        return None
