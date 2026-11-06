"""Fleet relay: buffered shipment of ``phptopwn.event/1.0`` records to a collector.

The sensor writes every request record to the same JSONL telemetry stream it
has always written.  When fleet forwarding is enabled the artifact store also
appends each record to a dedicated outbox file, and this module ships it in
NDJSON batches to ``[fleet].collector_url`` over HTTPS with a bearer token.

Design properties:

- Outage-safe: shipped progress is recorded as a byte offset in a state file.
  If the collector cannot be reached, events stay in the outbox and shipping
  resumes later, oldest first.  A crash between ship and offset advance
  re-sends an already-shipped batch; the collector dedupes per ``request_id``.
- Ring-capped: if the unshipped backlog exceeds ``max_buffer_bytes``, the
  oldest segment is skipped (never shipped) and the skip is counted and
  logged.  Collector retention is total for what arrives; sensor-side
  retention is bounded on purpose so a multi-day outage cannot fill the disk.
- Single egress: the forwarder talks only to ``[fleet].collector_url``.
"""
from __future__ import annotations

import json
import logging
import os
import threading
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from typing import Any
from uuid import uuid4

from . import __version__
from .config import Config

LOG = logging.getLogger("phptopwn.fleet")

_STATE_VERSION = 1
_DROP_LOOKAHEAD_BYTES = 1024 * 1024
_TRUNCATE_AFTER_BYTES = 64 * 1024 * 1024


def _normalize_url(url: str) -> str:
    return url[:-1] if url.endswith("/") else url


@dataclass
class OutboxSink:
    """Append event records to the fleet outbox as JSON lines (thread-safe)."""

    path: Any
    _lock: threading.Lock = field(repr=False)
    _handle: Any = field(default=None, repr=False)

    def open(self) -> None:
        with self._lock:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            if self._handle is None or self._handle.closed:
                self._handle = self.path.open("a", encoding="utf-8")

    def write(self, record: dict[str, Any]) -> int:
        """Append one event record; returns bytes written (0 if closed)."""
        line = json.dumps(record, ensure_ascii=False, default=str) + "\n"
        with self._lock:
            if self._handle is None or self._handle.closed:
                return 0
            self._handle.write(line)
            self._handle.flush()
        return len(line.encode("utf-8"))

    def size(self) -> int:
        with self._lock:
            if self._handle is None or self._handle.closed:
                return self.path.stat().st_size if self.path.exists() else 0
            return os.fstat(self._handle.fileno()).st_size

    def close(self) -> None:
        with self._lock:
            if self._handle is not None and not self._handle.closed:
                self._handle.close()

    def truncate(self) -> None:
        """Cut the outbox to zero; caller must hold the forwarder duty cycle."""
        with self._lock:
            if self._handle is None or self._handle.closed:
                raise RuntimeError("outbox is not open")
            self._handle.seek(0)
            self._handle.truncate()
            self._handle.flush()


@dataclass
class _Batch:
    """One ready unit of work from the outbox.

    ``lines`` holds complete JSON lines to ship, ``end_offset`` is the
    absolute byte position after this batch's data.  ``drop_bytes > 0``
    signals an overflow skip: nothing is shipped and ``end_offset`` already
    lands on a line boundary past the dropped stretch.
    """

    lines: list[str]
    end_offset: int
    drop_bytes: int = 0


class FleetForwarder:
    """Background thread shipping queued events from the outbox file."""

    def __init__(self, cfg: Config, metrics: Any | None = None) -> None:
        fleet = cfg.fleet
        self.cfg = cfg
        self.metrics = metrics
        self.url = _normalize_url(fleet.collector_url)
        self.token = fleet.collector_token
        self.node_id = fleet.node_id
        self.region = fleet.region
        self.buffer_dir = fleet.buffer_dir
        self.outbox_path = fleet.buffer_dir / "outbox.jsonl"
        self.state_path = fleet.buffer_dir / "forwarder_state.json"
        self.lock = threading.Lock()
        self.sink = OutboxSink(self.outbox_path, self.lock)
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self.counters: dict[str, Any] = {
            "events_shipped": 0,
            "events_skipped": 0,
            "batches_failed": 0,
            "last_error": "",
        }

    # -- lifecycle -------------------------------------------------------------
    def start(self) -> None:
        self.buffer_dir.mkdir(parents=True, exist_ok=True)
        self.sink.open()
        self._thread = threading.Thread(target=self._run, name="fleet-forwarder", daemon=True)
        self._thread.start()
        LOG.info(
            "fleet forwarding enabled: node=%s region=%s collector=%s",
            self.node_id,
            self.region,
            self.url,
        )

    def stop(self) -> None:
        self._stop.set()
        if self._thread is not None:
            self._thread.join(timeout=30.0)
            self._thread = None
        self.sink.close()

    def counters_snapshot(self) -> dict[str, Any]:
        return dict(self.counters)

    def _run(self) -> None:
        while not self._stop.wait(max(0.2, self.cfg.fleet.flush_interval_seconds)):
            shipped = 0
            try:
                shipped = self._cycle()
            except Exception:
                self.counters["batches_failed"] += 1
                self.counters["last_error"] = "cycle failed"
                LOG.exception("fleet forwarder cycle failed")
            if (
                shipped == 0
                and self._state_offset() >= self.sink.size()
                and self.sink.size() > _TRUNCATE_AFTER_BYTES
            ):
                try:
                    self._truncate_outbox()
                except (OSError, RuntimeError):  # truncation stays best-effort
                    LOG.exception("fleet outbox truncation failed")

    # -- shipping loop ----------------------------------------------------------
    def _cycle(self) -> int:
        """Ship every ready batch until idle or transport failure."""
        shipped_total = 0
        while True:
            batch = self._collect_batch()
            if batch is None:
                break
            if batch.drop_bytes:
                self._apply_drop(batch.end_offset, batch.drop_bytes)
                continue
            if not batch.lines:
                self._advance(batch.end_offset)
                continue
            if self._ship(batch.lines):
                self._advance(batch.end_offset)
                shipped_total += len(batch.lines)
            else:
                break
        return shipped_total

    def _collect_batch(self) -> _Batch | None:
        fleet = self.cfg.fleet
        if not self.outbox_path.exists():
            return None
        offset = self._state_offset()
        size = self.sink.size()
        if offset > size:
            LOG.warning("fleet state offset %d beyond outbox size %d; rescanning", offset, size)
            offset = 0
        if offset >= size:
            return None
        with self.outbox_path.open("rb") as handle:
            handle.seek(offset)
            data = handle.read(fleet.max_buffer_bytes + _DROP_LOOKAHEAD_BYTES)
        if not data:
            return None
        pending = len(data)
        if pending > fleet.max_buffer_bytes:
            skip = self._align_drop(data, pending - fleet.max_buffer_bytes)
            return _Batch([], offset + skip, skip)
        lines, consumed = self._split_lines(data)
        if not lines and not consumed:
            return None  # only a partial (still-growing) line is buffered
        return _Batch(lines, offset + consumed)

    @staticmethod
    def _align_drop(data: bytes, start: int) -> int:
        """Extend a drop boundary to end-of-line so no partial line survives."""
        newline = data.find(b"\n", start)
        if newline == -1:
            return len(data)
        return min(newline + 1, len(data))

    def _split_lines(self, data: bytes) -> tuple[list[str], int]:
        """Split buffered bytes into complete JSON lines within batch caps.

        Blank lines consume bytes but produce no batch entries.  A single
        oversized first line still ships alone; the collector enforces its
        own per-line cap and reports the rejection.
        """
        fleet = self.cfg.fleet
        lines: list[str] = []
        consumed = 0
        budget = fleet.batch_max_bytes
        for raw_line in data.splitlines(keepends=True):
            if not raw_line.endswith(b"\n"):
                break  # partial line: waits for the writer to finish it
            if len(raw_line) > budget and lines:
                break  # budget reached; ship what we have
            text = raw_line.decode("utf-8", "replace")
            consumed += len(raw_line)
            if text.strip():
                lines.append(text)
            budget -= len(raw_line)
            if len(lines) >= fleet.batch_max or budget <= 0:
                break
        return lines, consumed

    def _apply_drop(self, end_offset: int, skip_bytes: int) -> None:
        self.counters["events_skipped"] += max(1, skip_bytes // 1024)
        self.counters["last_error"] = f"backlog overflow: skipped {skip_bytes} bytes"
        LOG.warning("fleet backlog overflow: shipping resumed %d bytes later", skip_bytes)
        if self.metrics is not None:
            metrics = self.metrics
            metrics.counters["fleet_event_skips"] = (
                metrics.counters.get("fleet_event_skips", 0) + 1
            )
        self._advance(end_offset)

    # -- state persistence -------------------------------------------------------
    def _state_offset(self) -> int:
        try:
            state = json.loads(self.state_path.read_text(encoding="utf-8"))
            if int(state.get("v", 0)) == _STATE_VERSION:
                return max(0, int(state["offset"]))
        except (OSError, ValueError, KeyError, TypeError):
            pass
        return 0

    def _advance(self, offset: int) -> None:
        state = {"v": _STATE_VERSION, "offset": int(offset), "advanced_at": int(time.time())}
        tmp_path = self.state_path.with_name(f".{self.state_path.name}.{uuid4().hex[:8]}.tmp")
        try:
            tmp_path.write_text(json.dumps(state), encoding="utf-8")
            os.replace(tmp_path, self.state_path)
        except OSError:  # losing state replays from zero; collector dedupes
            tmp_path.unlink(missing_ok=True)

    def _truncate_outbox(self) -> None:
        self.sink.truncate()
        self._advance(0)
        LOG.info("fleet outbox truncated after full shipment")

    # -- transport -----------------------------------------------------------------
    def _ship(self, lines: list[str]) -> bool:
        payload = "".join(lines).encode("utf-8")
        request = urllib.request.Request(
            f"{self.url}/v1/events",
            data=payload,
            method="POST",
            headers={
                "Content-Type": "application/x-ndjson",
                "Authorization": f"Bearer {self.token}",
                "X-Phptopwn-Node": self.node_id,
                "X-Phptopwn-Region": self.region,
                "User-Agent": f"phptopwn-fleet/{__version__}",
            },
        )
        try:
            with urllib.request.urlopen(  # noqa: S310 - https enforced by config
                request, timeout=self.cfg.fleet.timeout_seconds
            ) as response:
                response.read()
                if 200 <= response.status < 300:
                    self._record_shipment(len(lines), len(payload))
                    return True
                reason = f"collector HTTP {response.status}"
        except urllib.error.HTTPError as exc:
            reason = f"collector HTTP {exc.code}"
        except (urllib.error.URLError, OSError, TimeoutError) as exc:
            reason = f"collector unreachable: {exc}"
        self.counters["batches_failed"] += 1
        self.counters["last_error"] = reason
        LOG.warning("fleet batch of %d events not shipped (%s)", len(lines), reason)
        return False

    def _record_shipment(self, count: int, payload_bytes: int) -> None:
        self.counters["events_shipped"] += count
        if self.metrics is not None:
            metrics = self.metrics
            metrics.counters["fleet_events_shipped"] = (
                metrics.counters.get("fleet_events_shipped", 0) + count
            )
            metrics.counters["fleet_bytes_shipped"] = (
                metrics.counters.get("fleet_bytes_shipped", 0) + payload_bytes
            )
