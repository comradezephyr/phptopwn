"""Runtime state: source guard, metrics accounting, retention loop, sensor."""
from __future__ import annotations

import asyncio
from dataclasses import replace as dc_replace

from conftest import build_capture, make_cfg

from phptopwn import runtime
from phptopwn.capture import Analysis, Signal
from phptopwn.runtime import Metrics, Sensor, SourceGuard, retention_loop
from phptopwn.storage import utc_now


def _capture(client_ip="203.0.113.5"):
    capture = build_capture(body=b"payload bytes", client_ip=client_ip)
    capture.analysis = Analysis(is_exploit=True, severity="high")
    return capture


def _signal_capture(signal_id):
    capture = build_capture(body=b"x")
    capture.analysis = Analysis(signals=[Signal(id=signal_id, severity="high", description="d")], is_exploit=True)
    return capture


def test_source_guard_rate_limit():
    guard = SourceGuard(max_concurrent=0, rate_per_minute=2)
    assert guard.acquire("1.1.1.1") is None
    assert guard.acquire("1.1.1.1") is None
    assert guard.acquire("1.1.1.1") == "rate_limited"


def test_source_guard_concurrency_limit_and_release():
    guard = SourceGuard(max_concurrent=1, rate_per_minute=0)
    assert guard.acquire("2.2.2.2") is None
    assert guard.acquire("2.2.2.2") == "concurrent_limit"
    guard.release("2.2.2.2")
    assert guard.acquire("2.2.2.2") is None


def test_source_guard_zero_disables():
    guard = SourceGuard(max_concurrent=0, rate_per_minute=0)
    assert guard.acquire("9.9.9.9") is None
    assert guard.release("9.9.9.9") is None


def test_source_guard_lru_eviction(monkeypatch):
    guard = SourceGuard(max_concurrent=0, rate_per_minute=1)
    guard._capacity = 2
    guard.acquire("a")
    guard.acquire("b")
    guard.acquire("c")
    assert set(guard._recent) == {"b", "c"}


def test_metrics_counts_and_signature_caps(monkeypatch):
    metrics = Metrics()
    monkeypatch.setattr(runtime, "_MAX_TRACKED_SIGNALS", 2)
    for signal_id in ("s1", "s2", "s3"):
        metrics.observe_capture(_signal_capture(signal_id))
    assert metrics.counters["exploits"] == 3
    assert metrics.counters["benign"] == 0
    assert set(metrics.signatures) <= {"s2", "s3"}  # oldest removed

    benign = build_capture(body=b"y")
    metrics.observe_capture(benign)
    assert metrics.counters["benign"] == 1
    assert metrics.body_bytes == 3 * len("x") + len("y")  # 3 signal captures + 1 benign

    metrics.observe_guard("rate_limited", "5.5.5.5")
    assert metrics.counters["rate_limited"] == 1
    assert metrics.counters["requests"] == 5  # 3 exploits + 1 benign + 1 guard rejection


def test_metrics_rate_top_sources_and_snapshot():
    metrics = Metrics()
    for _ in range(7):
        metrics.observe_capture(_capture(client_ip="7.7.7.7"))
    metrics.observe_capture(_capture(client_ip="8.8.8.8"))
    assert metrics.top_sources()[0] == {"ip": "7.7.7.7", "requests": 7}
    rate = metrics.request_rate()
    assert rate > 0

    snapshot = metrics.snapshot()
    for key in (
        "started_at",
        "uptime_seconds",
        "counters",
        "signatures",
        "top_sources",
        "request_rate_per_minute",
        "body_bytes_observed",
        "last_exploit_at",
    ):
        assert key in snapshot
    assert snapshot["body_bytes_observed"] > 0


def test_metrics_ip_eviction(monkeypatch):
    metrics = Metrics()
    monkeypatch.setattr(runtime, "_MAX_TRACKED_IPS", 3)
    for ip in ("a", "b", "c", "d"):
        metrics.observe_capture(_capture(client_ip=ip))
    assert set(metrics.ip_totals) <= {"b", "c", "d"}


def test_sensor_open_and_shutdown(tmp_path):
    sensor = Sensor(make_cfg(tmp_path))
    sensor.open()
    assert sensor.store.log_path.parent.exists()
    assert sensor.alerts.webhook_url == ""

    async def driver():
        await sensor.shutdown()  # empty maintenance list + no client

    asyncio.run(driver())


def test_retention_loop_runs_until_cancelled(tmp_path, monkeypatch):
    calls: list[tuple] = []

    def fake_sweep(cfg, capture_dir, log_dir):
        calls.append((cfg, capture_dir, log_dir))
        return {"captures_removed": 1, "logs_rotated": 0}

    monkeypatch.setattr(runtime, "retention_sweep", fake_sweep)
    base = make_cfg(tmp_path)
    tightened = dc_replace(base.retention, sweep_interval_seconds=0.05)
    cfg = dc_replace(base, retention=tightened)

    async def driver():
        task = asyncio.create_task(retention_loop(cfg))
        try:
            for _ in range(200):
                await asyncio.sleep(0.01)
                if len(calls) >= 3:
                    break
        finally:
            task.cancel()
            await asyncio.gather(task, return_exceptions=True)

    asyncio.run(driver())
    assert len(calls) >= 3
    for _, capture_dir, log_dir in calls:
        assert capture_dir.name == "payloads"
        assert log_dir.name == "logs"


def test_sensor_maintenance_task_is_cancelled_on_shutdown(tmp_path):
    sensor = Sensor(make_cfg(tmp_path))
    triggered: list[str] = []

    async def fake_loop(cfg):
        triggered.append("running")
        await asyncio.sleep(3600)

    import phptopwn.runtime as rt

    original = rt.retention_loop
    rt.retention_loop = fake_loop  # type: ignore[assignment]
    try:
        assert not sensor._tasks

        async def driver():
            sensor.start_maintenance()
            assert sensor._tasks
            await asyncio.sleep(0.05)
            await sensor.shutdown()

        asyncio.run(driver())
        assert triggered == ["running"]
        assert sensor._tasks == []
    finally:
        rt.retention_loop = original  # type: ignore[assignment]


def test_utc_now_formatting():
    stamp = utc_now()
    assert stamp.endswith("Z") and "T" in stamp and len(stamp) == 24


def test_build_capture_defaults_match_middleware_shape():
    capture = build_capture(body=b"abc", headers={"Content-Type": "text/plain"})
    assert capture.declared_content_length == 3
    assert capture.body_probe == b"abc"
    assert capture.header_count == 1
    assert capture.max_chunk_gap == 0.0
    assert capture.content_type == "text/plain"
