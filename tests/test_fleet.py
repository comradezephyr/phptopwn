"""Fleet relay: config validation, outbox sink, forwarder shipping and drops."""
from __future__ import annotations

import json
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

import pytest
from conftest import make_cfg, wait_for

from phptopwn.config import ConfigError, load_config
from phptopwn.fleet import FleetForwarder, OutboxSink
from phptopwn.runtime import Sensor

TOKEN = "t" * 40


def fleet_cfg(tmp: Path, port: int, **fleet: object) -> object:
    values: dict[str, object] = {
        "enabled": "true",
        "node_id": "lab-eu-1",
        "region": "eu-test",
        "collector_url": f"http://127.0.0.1:{port}",
        "collector_token": TOKEN,
        "buffer_dir": str(tmp / "fleet"),
        "flush_interval_seconds": "0.5",
        "timeout_seconds": "3",
    }
    values.update(fleet)
    env = {f"PHPTOPWN_{key.upper()}": str(value) for key, value in values.items()}
    return load_config(environ=env)


class _FakeMetrics:
    def __init__(self) -> None:
        self.counters: dict[str, int] = {"fleet_events_shipped": 0}


class _CollectorStub:
    """Tiny stand-in for the collector ingest endpoint (200 or 500)."""

    def __init__(self, respond: int = 200) -> None:
        self.requests: list[dict] = []
        self.respond = respond
        self._lock = threading.Lock()
        self._server = HTTPServer(("127.0.0.1", 0), _make_handler(self))
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)
        self._thread.start()

    @property
    def port(self) -> int:
        assert self._server.server_address is not None
        host, port = self._server.server_address
        assert isinstance(port, int)
        return port

    def stop(self) -> None:
        self._server.shutdown()
        self._server.server_close()
        self._thread.join(timeout=2)
        self._thread = None  # type: ignore[assignment]


def _make_handler(stub: _CollectorStub) -> type[BaseHTTPRequestHandler]:
    class _Handler(BaseHTTPRequestHandler):
        def do_POST(self) -> None:  # noqa: N802
            length = int(self.headers.get("content-length", "0"))
            body = self.rfile.read(length)
            with stub._lock:
                stub.requests.append(
                    {
                        "path": self.path,
                        "headers": {k.lower(): v for k, v in self.headers.items()},
                        "body": body,
                    }
                )
            code = 503 if stub.respond != 200 else 200
            self.send_response(code)
            self.end_headers()
            self.wfile.write(b'{"accepted": 0}')

        def log_message(self, *args: object) -> None:
            pass

    return _Handler


def _records(count: int, pad: int = 0) -> list[dict]:
    return [
        {
            "schema": "phptopwn.event/1.0",
            "event": "http_request",
            "request_id": f"task-{index}",
            "timestamp": "2026-02-03T04:05:06.007Z",
            "client": {"ip": "192.0.2.8", "port": 1337},
            "request": {"method": "POST", "path": "/x.php"},
            "analysis": {"is_exploit": True},
            "pad": "a" * pad,
        }
        for index in range(count)
    ]


# --- configuration -------------------------------------------------------------
def test_fleet_disabled_by_default():
    cfg = load_config(environ={})
    assert cfg.fleet.enabled is False


@pytest.mark.parametrize(
    "bad_field, bad_value",
    [
        ("node_id", "BAD NODE"),
        ("region", "EU@west"),
        ("collector_url", "http://fleet.example.com"),
        ("collector_token", "short"),
        ("batch_max", "8"),
        ("batch_max_bytes", "1024"),
        ("flush_interval_seconds", "0.1"),
        ("timeout_seconds", "0.5"),
    ],
)
def test_fleet_config_validation_rejects(tmp_path, bad_field, bad_value):
    with pytest.raises(ConfigError):
        fleet_cfg(tmp_path, 9443, **{bad_field: bad_value})


def test_fleet_config_valid(tmp_path):
    cfg = fleet_cfg(tmp_path, 9443)
    assert cfg.fleet.enabled is True
    assert cfg.fleet.node_id == "lab-eu-1"
    assert cfg.fleet.buffer_dir == tmp_path / "fleet"


# --- outbox sink ---------------------------------------------------------------
def test_outbox_sink_write_roundtrip(tmp_path):
    sink = OutboxSink(tmp_path / "outbox.jsonl", threading.Lock())
    sink.open()
    record = _records(1)[0]
    written = sink.write(record)
    line = json.dumps(record) + "\n"
    assert written == len(line.encode("utf-8"))
    assert sink.size() >= written
    assert (tmp_path / "outbox.jsonl").read_text(encoding="utf-8") == line
    sink.close()
    assert sink.write(record) == 0
    with pytest.raises(RuntimeError):
        sink.truncate()


def test_outbox_sink_truncate(tmp_path):
    sink = OutboxSink(tmp_path / "outbox.jsonl", threading.Lock())
    sink.open()
    sink.write(_records(1)[0])
    sink.truncate()
    assert sink.size() == 0
    sink.close()


# --- forwarder -----------------------------------------------------------------
def test_forwarder_ships_batches_to_collector(tmp_path):
    stub = _CollectorStub()
    try:
        cfg = fleet_cfg(tmp_path, stub.port)
        metrics = _FakeMetrics()
        fwd = FleetForwarder(cfg, metrics)
        sink = fwd.sink
        sink.open()
        for record in _records(3):
            sink.write(record)
        backlog_size = sink.size()
        fwd.start()
        try:
            assert wait_for(lambda: len(stub.requests) >= 1)
            assert wait_for(lambda: fwd._state_offset() >= backlog_size)
            assert fwd.counters["events_shipped"] == 3
            assert metrics.counters["fleet_events_shipped"] == 3
            batch = stub.requests[0]
            assert batch["path"] == "/v1/events"
            assert batch["headers"]["authorization"] == f"Bearer {TOKEN}"
            assert batch["headers"]["x-phptopwn-node"] == "lab-eu-1"
            assert batch["headers"]["x-phptopwn-region"] == "eu-test"
            assert "ndjson" in batch["headers"]["content-type"]
            received = [json.loads(line) for line in batch["body"].decode().splitlines()]
            assert [r["request_id"] for r in received] == ["task-0", "task-1", "task-2"]
        finally:
            fwd.stop()
    finally:
        stub.stop()


def test_forwarder_keeps_backlog_when_collector_fails(tmp_path):
    stub = _CollectorStub(respond=503)
    try:
        cfg = fleet_cfg(tmp_path, stub.port)
        fwd = FleetForwarder(cfg, None)
        fwd.sink.open()
        for record in _records(2):
            fwd.sink.write(record)
        fwd.start()
        try:
            assert wait_for(lambda: fwd.counters["batches_failed"] >= 1)
            short_wait = wait_for(lambda: fwd.counters["events_shipped"] > 0, timeout=0.8)
            assert short_wait is None
            assert fwd._state_offset() == 0
            assert "503" in fwd.counters["last_error"]
        finally:
            fwd.stop()
    finally:
        stub.stop()


def test_forwarder_drops_backlog_on_overflow(tmp_path):
    stub = _CollectorStub()
    try:
        cfg = fleet_cfg(
            tmp_path,
            stub.port,
            batch_max_bytes="65536",
            max_buffer_bytes="262144",
            batch_max="256",
        )
        fwd = FleetForwarder(cfg, None)
        fwd.sink.open()
        for record in _records(200, pad=2000):
            fwd.sink.write(record)
        backlog_size = fwd.sink.size()
        assert backlog_size > 262144
        fwd.start()
        try:
            assert wait_for(lambda: fwd.counters["events_skipped"] > 0)
            assert "overflow" in fwd.counters["last_error"]
            assert wait_for(lambda: fwd._state_offset() == backlog_size)
            assert fwd.counters["events_shipped"] > 0
            assert len(stub.requests) >= 1
        finally:
            fwd.stop()
    finally:
        stub.stop()


def test_forwarder_rescans_when_state_outlives_outbox(tmp_path):
    buf = tmp_path / "fleet"
    buf.mkdir(parents=True)
    (buf / "forwarder_state.json").write_text('{"v": 1, "offset": 999999}', encoding="utf-8")
    cfg = fleet_cfg(tmp_path, 9443, flush_interval_seconds="600")
    fwd = FleetForwarder(cfg, None)
    fwd.sink.open()
    fwd.sink.write(_records(1)[0])
    batch = fwd._collect_batch()
    assert batch is not None and not batch.drop_bytes
    assert batch.lines and "task-0" in batch.lines[0]
    assert batch.end_offset == fwd.sink.size()
    fwd.sink.close()


def test_forwarder_state_advance_is_atomic(tmp_path):
    cfg = fleet_cfg(tmp_path, 9443)
    fwd = FleetForwarder(cfg, None)
    fwd.buffer_dir.mkdir(parents=True, exist_ok=True)
    fwd._advance(4096)
    assert fwd._state_offset() == 4096
    fwd._advance(0)
    assert fwd._state_offset() == 0


def test_forwarder_truncates_outbox_once_shipped(tmp_path):
    cfg = fleet_cfg(tmp_path, 9443)
    fwd = FleetForwarder(cfg, None)
    fwd.buffer_dir.mkdir(parents=True, exist_ok=True)
    fwd.sink.open()
    for record in _records(2):
        fwd.sink.write(record)
    fwd._advance(fwd.sink.size())
    assert fwd.sink.size() > 0
    fwd._truncate_outbox()
    assert fwd.sink.size() == 0
    assert fwd._state_offset() == 0
    fwd.sink.close()


def test_forwarder_skips_blank_lines(tmp_path):
    stub = _CollectorStub()
    try:
        cfg = fleet_cfg(tmp_path, stub.port)
        fwd = FleetForwarder(cfg, None)
        fwd.sink.open()
        fwd.sink.write(_records(1)[0])
        with fwd.outbox_path.open("a", encoding="utf-8") as handle:
            handle.write("\n\n")
        fwd.sink.write(_records(1)[0])
        blank_size = fwd.sink.size()
        fwd.start()
        try:
            assert wait_for(lambda: fwd._state_offset() >= blank_size)
            received = [
                json.loads(line)
                for line in stub.requests[0]["body"].decode().splitlines()
                if line.strip()
            ]
            assert len(received) == 2
        finally:
            fwd.stop()
    finally:
        stub.stop()


# --- runtime wiring ------------------------------------------------------------
def test_sensor_registers_event_sink_when_fleet_enabled(tmp_path):
    cfg = fleet_cfg(tmp_path, 9443)  # type: ignore[arg-type]
    sensor = Sensor(cfg)
    assert sensor.fleet is not None
    assert sensor.fleet.node_id == "lab-eu-1"
    sensor.open()
    assert sensor.store._event_sink == sensor.fleet.sink.write
    sensor.fleet.sink.open()
    record = _records(1)[0]
    sensor.fleet.sink.write(record)
    assert (tmp_path / "fleet" / "outbox.jsonl").exists()


def test_sensor_without_fleet_has_no_forwarder(tmp_path):
    sensor = Sensor(make_cfg(tmp_path))
    assert sensor.fleet is None
