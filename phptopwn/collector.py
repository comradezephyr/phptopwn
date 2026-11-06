"""Regional collector: fleet event ingest, dedupe, retention and dashboard.

The collector is a separate service from the sensor. Sensors POST NDJSON
batches of ``phptopwn.event/1.0`` records to ``/v1/events``; every accepted
event is enriched with ``{"collector": {"node", "region", "received_at"}}``
and appended to a day-partitioned, append-only raw store on a bind volume.

Retention is total: raw day files are never rewritten or pruned by the
collector. Data leaves the collector only through operator-invoked exports
(``phptopwn-collect ioc``) — there are no outbound integrations.

Ingest rejects and reports per-line problems in the response body instead of
failing the whole batch, so a sensor never re-sends an unshippable batch
forever. Identity fields (``schema``, ``request_id``, ``timestamp``,
``client.ip``, ``request.method``, ``request.path``) are validated; the
dedupe window is a bounded number of days by ``request_id`` — re-sends after
a crash between ship and offset advance are dropped here.
"""
from __future__ import annotations

import hmac
import json
import logging
import re
import threading
import time
import tomllib
from collections import OrderedDict, deque
from collections.abc import Iterator
from dataclasses import dataclass, field, fields
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from fastapi import FastAPI, Request, Response
from fastapi.responses import HTMLResponse, JSONResponse

LOG = logging.getLogger("phptopwn.collector")

EVENT_SCHEMA = "phptopwn.event/1.0"

_ID_RE = re.compile(r"[a-z0-9][a-z0-9-]{0,63}")
_REQUEST_ID_RE = re.compile(r"[A-Za-z0-9._:-]{1,128}")
_TIMESTAMP_RE = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?(Z|[+-]\d{2}:\d{2})?")
_SEEN_CAPACITY = 600_000


class CollectConfigError(ValueError):
    pass


@dataclass(frozen=True)
class CollectConfig:
    host: str = "127.0.0.1"
    port: int = 9443
    tls_enabled: bool = False
    cert_file: Path = field(default_factory=lambda: Path("certs/collector.crt"))
    key_file: Path = field(default_factory=lambda: Path("certs/collector.key"))
    ingest_token: str = ""
    data_dir: Path = field(default_factory=lambda: Path("collector-data"))
    dashboard: bool = True
    max_event_bytes: int = 2 * 1024 * 1024
    max_batch_bytes: int = 32 * 1024 * 1024
    max_batch_events: int = 8192
    dedupe_days: int = 3
    ingest_rate_per_minute: int = 600


def utc_now() -> str:
    return datetime.now(UTC).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def read_collect_config(path: Path) -> tuple[CollectConfig, dict[str, str]]:
    try:
        loaded = tomllib.loads(path.read_text(encoding="utf-8"))
    except tomllib.TOMLDecodeError as exc:
        raise CollectConfigError(f"invalid TOML in {path}: {exc}") from exc
    except OSError as exc:
        raise CollectConfigError(f"cannot read collector config {path}: {exc}") from exc
    data = loaded.get("collector", {})
    nodes = loaded.get("nodes", {})
    if not isinstance(data, dict):
        raise CollectConfigError("collector: must be a table")
    if not isinstance(nodes, dict):
        raise CollectConfigError('nodes: must be a table of node_id = "region"')
    valid = {f.name for f in fields(CollectConfig)}
    unknown = set(data) - valid
    if unknown:
        raise CollectConfigError(f"unknown key in [collector]: {', '.join(sorted(unknown))}")
    values: dict[str, Any] = {}
    for name in valid:
        if name not in data:
            continue
        raw = data[name]
        if name in ("cert_file", "key_file", "data_dir"):
            if not isinstance(raw, str):
                raise CollectConfigError(f"collector.{name}: expected a string path")
            values[name] = Path(raw)
        elif isinstance(raw, (str, bool, int, float)):
            values[name] = raw
        else:
            raise CollectConfigError(f"collector.{name}: expected a scalar value")
    cfg = CollectConfig(**values)
    node_map: dict[str, str] = {}
    for node_id, region in nodes.items():
        if not isinstance(node_id, str) or not _ID_RE.fullmatch(node_id):
            raise CollectConfigError(f"nodes: '{node_id}' must be 1-64 chars of [a-z0-9-]")
        if not isinstance(region, str) or not _ID_RE.fullmatch(region):
            raise CollectConfigError(
                f"nodes: region of '{node_id}' must be 1-64 chars of [a-z0-9-]"
            )
        node_map[node_id] = region
    _validate_collect_config(cfg)
    return cfg, node_map


def _validate_collect_config(cfg: CollectConfig) -> None:
    if not 1 <= cfg.port <= 65535:
        raise CollectConfigError(f"collector: port {cfg.port} is not a valid port")
    if len(cfg.ingest_token) < 32 or any(ch.isspace() for ch in cfg.ingest_token):
        raise CollectConfigError("collector: ingest_token must be >=32 chars without whitespace")
    if cfg.host.strip() == "":
        raise CollectConfigError("collector: host must not be empty")
    if cfg.data_dir in (Path("/"), Path(".")):
        raise CollectConfigError("collector: data_dir must be a dedicated directory")
    if not 16384 <= cfg.max_event_bytes <= 8 * 1024 * 1024:
        raise CollectConfigError("collector: max_event_bytes must be within 16 KiB..8 MiB")
    if cfg.max_batch_bytes < cfg.max_event_bytes:
        raise CollectConfigError("collector: max_batch_bytes must be >= max_event_bytes")
    if not 16 <= cfg.max_batch_events <= 65536:
        raise CollectConfigError("collector: max_batch_events must be within 16..65536")
    if not 1 <= cfg.dedupe_days <= 90:
        raise CollectConfigError("collector: dedupe_days must be between 1 and 90")
    if cfg.ingest_rate_per_minute < 0:
        raise CollectConfigError("collector: ingest_rate_per_minute must be >= 0 (0 disables)")


def validate_event(line: str) -> tuple[dict[str, Any] | None, str | None]:
    """Validate one event line; returns (record, error_code)."""
    try:
        record = json.loads(line)
    except (json.JSONDecodeError, ValueError):
        return None, "invalid_json"
    if not isinstance(record, dict):
        return None, "invalid_json"
    if record.get("schema") != EVENT_SCHEMA:
        return None, "schema_mismatch"
    if record.get("event", "http_request") != "http_request":
        return None, "invalid_shape:event"
    request_id = record.get("request_id")
    if not isinstance(request_id, str) or not _REQUEST_ID_RE.fullmatch(request_id):
        return None, "invalid_shape:request_id"
    timestamp = record.get("timestamp")
    if not isinstance(timestamp, str) or not _TIMESTAMP_RE.fullmatch(timestamp):
        return None, "invalid_shape:timestamp"
    client = record.get("client")
    if not isinstance(client, dict):
        return None, "invalid_shape:client"
    ip = client.get("ip")
    if not isinstance(ip, str) or not 1 <= len(ip) <= 64:
        return None, "invalid_shape:client.ip"
    request = record.get("request")
    if not isinstance(request, dict):
        return None, "invalid_shape:request"
    method = request.get("method")
    if not isinstance(method, str) or not 1 <= len(method) <= 16:
        return None, "invalid_shape:request.method"
    path = request.get("path")
    if not isinstance(path, str) or not 1 <= len(path) <= 2048:
        return None, "invalid_shape:request.path"
    return record, None


def day_of(record: dict[str, Any]) -> str:
    """UTC calendar day (YYYYMMDD) the event timestamp falls on."""
    return record["timestamp"][:10].replace("-", "")


class EventStore:
    """Append-only day-partitioned raw store with a bounded dedupe window."""

    def __init__(self, cfg: CollectConfig, node_map: dict[str, str]) -> None:
        self.cfg = cfg
        self.raw_dir = cfg.data_dir / "raw"
        self.ids_dir = cfg.data_dir / "ids"
        self.node_map = dict(node_map)
        self._lock = threading.Lock()
        self._seen: OrderedDict[str, None] = OrderedDict()
        self._opened = False

    def open(self) -> None:
        if self._opened:
            return
        self.raw_dir.mkdir(parents=True, exist_ok=True)
        self.ids_dir.mkdir(parents=True, exist_ok=True)
        self._load_seen()
        self._opened = True

    def _load_seen(self) -> None:
        base = datetime.now(UTC).date()
        for age in range(self.cfg.dedupe_days):
            day = (base - timedelta(days=age)).strftime("%Y%m%d")
            ids_path = self.ids_dir / f"{day}.ids"
            if not ids_path.exists():
                continue
            try:
                with ids_path.open("r", encoding="utf-8") as handle:
                    for line in handle:
                        request_id = line.strip()
                        if request_id:
                            self._seen[request_id] = None
            except OSError:  # pragma: no cover - unreadable index keeps working
                LOG.exception("failed to load dedupe index %s", ids_path)
        self._trim_seen()

    def _trim_seen(self) -> None:
        while len(self._seen) > _SEEN_CAPACITY:
            self._seen.popitem(last=False)

    def append(self, node: str, region: str, records: list[dict[str, Any]]) -> tuple[int, int]:
        """Store accepted records; returns (accepted, duplicates)."""
        accepted = 0
        duplicates = 0
        prepared: dict[str, tuple[list[str], list[str]]] = {}
        with self._lock:
            for record in records:
                request_id = record["request_id"]
                if request_id in self._seen:
                    duplicates += 1
                    continue
                self._seen[request_id] = None
                record["collector"] = {
                    "node": node,
                    "region": region,
                    "received_at": utc_now(),
                }
                day = day_of(record)
                lines, ids = prepared.setdefault(day, ([], []))
                lines.append(json.dumps(record, ensure_ascii=False, default=str) + "\n")
                ids.append(request_id + "\n")
                accepted += 1
            self._trim_seen()
            for day, (lines, ids) in prepared.items():
                with (self.raw_dir / f"{day}.jsonl").open("a", encoding="utf-8") as handle:
                    handle.writelines(lines)
                with (self.ids_dir / f"{day}.ids").open("a", encoding="utf-8") as handle:
                    handle.writelines(ids)
        return accepted, duplicates

    def available_days(self) -> list[str]:
        return sorted(path.stem for path in self.raw_dir.glob("*.jsonl"))

    def iter_day(self, day: str) -> Iterator[dict[str, Any]]:
        path = self.raw_dir / f"{day}.jsonl"
        if not path.exists():
            return
        with path.open("r", encoding="utf-8", errors="replace") as handle:
            for line in handle:
                try:
                    yield json.loads(line)
                except (json.JSONDecodeError, ValueError):
                    continue

    def recent(self, limit: int = 100) -> list[dict[str, Any]]:
        """Newest events across all days, newest day first."""
        window: deque[dict[str, Any]] = deque(maxlen=max(1, limit))
        for day in reversed(self.available_days()):
            for record in self.iter_day(day):
                window.append(record)
            if len(window) >= limit:
                break
        return list(reversed(window))

    def summary(self, day: str) -> dict[str, Any]:
        totals = {"events": 0, "exploits": 0, "benign": 0}
        regions: dict[str, dict[str, int]] = {}
        nodes: dict[str, dict[str, int]] = {}
        unique_ips: set[str] = set()
        unique_paths: set[str] = set()
        for record in self.iter_day(day):
            analysis = record.get("analysis") or {}
            is_exploit = bool(analysis.get("is_exploit"))
            totals["events"] += 1
            totals["exploits"] += 1 if is_exploit else 0
            totals["benign"] += 0 if is_exploit else 1
            metarec = record.get("collector") or {}
            region = str(metarec.get("region", "unknown"))
            node = str(metarec.get("node", "unknown"))
            bucket = regions.setdefault(region, {"events": 0, "exploits": 0})
            bucket["events"] += 1
            bucket["exploits"] += 1 if is_exploit else 0
            node_bucket = nodes.setdefault(node, {"events": 0, "exploits": 0})
            node_bucket["events"] += 1
            node_bucket["exploits"] += 1 if is_exploit else 0
            client = record.get("client") or {}
            request = record.get("request") or {}
            unique_ips.add(str(client.get("ip")))
            unique_paths.add(str(request.get("path"))[:256])
        return {
            "day": day,
            "totals": totals,
            "regions": regions,
            "nodes": nodes,
            "unique_ips": len(unique_ips),
            "unique_paths": len(unique_paths),
        }


class IngestGuard:
    """Per-remote-IP rolling-minute allowance for the ingest endpoint."""

    def __init__(self, limit_per_minute: int, capacity: int = 16384) -> None:
        self.limit = limit_per_minute
        self.capacity = capacity
        self._events: OrderedDict[str, deque[float]] = OrderedDict()
        self._lock = threading.Lock()

    def allow(self, ip: str) -> bool:
        if self.limit <= 0:
            return True
        now = time.monotonic()
        with self._lock:
            window = self._events.get(ip)
            if window is None:
                while len(self._events) >= self.capacity:
                    self._events.popitem(last=False)
                window = deque()
                self._events[ip] = window
            self._events.move_to_end(ip)
            while window and now - window[0] > 60.0:
                window.popleft()
            if len(window) >= self.limit:
                return False
            window.append(now)
            return True


def create_collector_app(cfg: CollectConfig, store: EventStore) -> FastAPI:
    """Build the collector FastAPI app: ingest endpoint, health, dashboard."""
    guard = IngestGuard(cfg.ingest_rate_per_minute)
    stats: dict[str, int] = {
        "events_accepted": 0,
        "events_duplicates": 0,
        "events_rejected": 0,
        "batches": 0,
    }

    app = FastAPI(title="phptopwn-collect", docs_url=None, redoc_url=None, openapi_url=None)

    @app.middleware("http")
    async def security_headers(request: Request, call_next: Any) -> Response:
        response: Response = await call_next(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "no-referrer"
        if request.method == "GET":
            response.headers["Content-Security-Policy"] = (
                "default-src 'none'; style-src 'unsafe-inline'"
            )
        return response

    @app.post("/v1/events")
    async def ingest(request: Request) -> Response:
        is_allowed = guard.allow(request.client.host if request.client else "")
        if not is_allowed:
            return JSONResponse({"error": "slow down"}, status_code=429)
        auth = request.headers.get("authorization", "")
        given = auth[7:] if auth.startswith("Bearer ") else ""
        if not hmac.compare_digest(given, cfg.ingest_token):
            stats["events_rejected"] += 1
            return JSONResponse({"error": "unauthorized"}, status_code=401)
        node = request.headers.get("x-phptopwn-node", "")
        region = store.node_map.get(node)
        if region is None:
            stats["events_rejected"] += 1
            return JSONResponse({"error": "unknown node"}, status_code=403)
        content_type = request.headers.get("content-type", "")
        if "ndjson" not in content_type.lower():
            return JSONResponse(
                {"error": "content-type must be application/x-ndjson"}, status_code=415
            )
        body = await request.body()
        if len(body) > cfg.max_batch_bytes:
            return JSONResponse(
                {"error": "batch exceeds configured maximum bytes"}, status_code=413
            )
        lines = body.split(b"\n")
        if lines and lines[-1] == b"":
            lines = lines[:-1]
        if len(lines) > cfg.max_batch_events:
            return JSONResponse(
                {"error": "batch exceeds configured maximum events"}, status_code=413
            )
        records: list[dict[str, Any]] = []
        rejected: dict[str, int] = {}
        total = 0
        for raw_line in lines:
            total += 1
            if len(raw_line) > cfg.max_event_bytes:
                rejected["line_too_large"] = rejected.get("line_too_large", 0) + 1
                continue
            line = raw_line.decode("utf-8", "replace")
            if not line.strip():
                rejected["blank"] = rejected.get("blank", 0) + 1
                continue
            record, error = validate_event(line)
            if error is not None or record is None:
                rejected[error or "invalid_json"] = rejected.get(error or "invalid_json", 0) + 1
                continue
            records.append(record)
        accepted, duplicates = (0, 0)
        if records:
            accepted, duplicates = store.append(node, region, records)
        stats["batches"] += 1
        stats["events_accepted"] += accepted
        stats["events_duplicates"] += duplicates
        stats["events_rejected"] += sum(rejected.values())
        return JSONResponse(
            {"accepted": accepted, "duplicates": duplicates, "rejected": rejected, "total": total}
        )

    @app.get("/healthz")
    async def healthz() -> Response:
        return JSONResponse(
            {"status": "ok", "stats": stats, "recent_days": store.available_days()[-3:]}
        )

    if cfg.dashboard:
        from . import dashboard as dash

        @app.get("/", response_class=HTMLResponse)
        async def overview() -> Response:
            return HTMLResponse(dash.render_overview(store))

        @app.get("/regions", response_class=HTMLResponse)
        async def regions() -> Response:
            return HTMLResponse(dash.render_regions(store))

        @app.get("/events", response_class=HTMLResponse)
        async def events(limit: int = 50) -> Response:
            clamped = max(1, min(500, limit))
            return HTMLResponse(dash.render_events(store.recent(clamped)))

    return app
