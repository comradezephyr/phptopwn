"""Internal listener: healthz JSON payload and Prometheus families."""
from __future__ import annotations

from datetime import UTC, datetime

from conftest import build_capture, make_cfg
from starlette.testclient import TestClient

from phptopwn.capture import Analysis, Signal
from phptopwn.metrics import SensorCollector, build_internal_app
from phptopwn.runtime import Sensor
from phptopwn.storage import ArtifactStore


def _populated_metrics():
    sensor = Sensor(make_cfg())
    metrics = sensor.metrics
    benign = build_capture(body=b"a=1", headers={"Content-Type": "application/x-www-form-urlencoded"})
    metrics.observe_capture(benign)

    exploit = build_capture(body=b"b=2", headers={"Content-Type": "application/x-www-form-urlencoded"})
    exploit.analysis = Analysis(
        signals=[Signal(id="scanner_user_agent", severity="low", description="x")],
        is_exploit=True,
        severity="low",
    )
    metrics.observe_capture(exploit)
    metrics.observe_guard("rate_limited", "198.51.100.4")
    metrics.observe_guard("header_flood", "198.51.100.5")
    metrics.counters["alerts_sent"] += 1
    metrics.counters["alerts_failed"] += 2
    metrics.last_exploit_at = "2026-11-01T12:00:00.000Z"
    return sensor


def test_sensor_collector_families():
    sensor = _populated_metrics()
    families = {family.name: family for family in list(SensorCollector(sensor.metrics).collect())}
    assert "phptopwn_requests" in families
    assert "phptopwn_uptime_seconds" in families
    assert "phptopwn_guard_rejections" in families
    assert "phptopwn_alerts" in families
    assert "phptopwn_last_exploit_at_seconds" in families

    requests = families["phptopwn_requests"]
    samples = {(s.labels["kind"], s.value) for s in requests.samples}
    assert ("benign", 1) in samples
    assert ("exploit", 1) in samples

    guard = families["phptopwn_guard_rejections"]
    guards = {(s.labels["reason"], s.value) for s in guard.samples}
    assert ("rate_limited", 1) in guards
    assert ("concurrent_limit", 0) in guards

    last = families["phptopwn_last_exploit_at_seconds"].samples[0].value
    assert last == datetime(2026, 11, 1, 12, 0, 0, tzinfo=UTC).timestamp()


def test_unix_parsing_edge_cases():
    assert SensorCollector._unix(None) == 0.0
    assert SensorCollector._unix("garbage") == 0.0
    stamp = datetime.fromisoformat("2026-11-01T12:00:00.000")
    assert SensorCollector._unix("2026-11-01T12:00:00.000") == stamp.timestamp()


def test_internal_listener_endpoints(tmp_path):
    sensor = _populated_metrics()
    sensor.store = ArtifactStore(make_cfg(tmp_path))
    client = TestClient(build_internal_app(sensor))

    healthz = client.get("/healthz")
    assert healthz.status_code == 200
    payload = healthz.json()
    assert payload["status"] == "ok" and payload["counters"]["exploits"] == 1
    assert payload["version"]

    metrics = client.get("/metrics")
    assert metrics.status_code == 200
    assert metrics.headers["content-type"].startswith("text/plain")
    text = metrics.text
    for series in (
        'phptopwn_requests_total{kind="exploit"}',
        "phptopwn_uptime_seconds",
        'phptopwn_alerts_total{outcome="failed"} 2',
        "phptopwn_last_exploit_at_seconds",
    ):
        assert series in text, series

    # the internal app never tracks decoy requests into exploit telemetry
    assert client.get("/metrics").headers["content-type"]
