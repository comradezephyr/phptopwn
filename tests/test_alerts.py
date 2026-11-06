"""Webhook alert hub: gating, metering, overflow, delivery accounting."""
from __future__ import annotations

import asyncio
import json
from dataclasses import replace as dc_replace
from types import SimpleNamespace

from conftest import build_capture, make_cfg

from phptopwn.alerts import AlertHub
from phptopwn.detection import analyze
from phptopwn.parsing import enrich_capture
from phptopwn.runtime import Metrics


def _exploit_capture():
    capture = build_capture(body=b"cmd=run", headers={"Content-Type": "application/x-www-form-urlencoded"})
    enrich_capture(capture)
    capture.analysis = analyze(capture, make_cfg())
    return capture


def _benign_capture():
    capture = build_capture(body=b"note=benign", headers={"Content-Type": "application/x-www-form-urlencoded"})
    enrich_capture(capture)
    capture.analysis = analyze(capture, make_cfg())
    return capture


class _FakeClient:
    def __init__(self, responses):
        self.responses = list(responses)
        self.posted: list = []
        self.closed = False

    async def post(self, url, json=None, **kwargs):
        self.posted.append((url, json))
        result = self.responses.pop(0)
        if isinstance(result, int):
            return SimpleNamespace(status_code=result)
        raise result  # an exception instance

    async def aclose(self):
        self.closed = True


def alert_hub(**overrides):
    cfg = make_cfg()
    alerts = dc_replace(cfg.alerts, webhook_url=overrides.pop("webhook_url", "http://hook.invalid/x"), **overrides)
    cfg = dc_replace(cfg, alerts=alerts)
    return AlertHub(cfg, Metrics())


def test_disabled_hub_is_noop():
    hub = AlertHub(make_cfg(), Metrics())
    hub.maybe_dispatch(_exploit_capture())
    assert hub._tasks == set()


def test_benign_analysis_skipped():
    hub = alert_hub()
    hub.maybe_dispatch(_benign_capture())
    assert hub._tasks == set()


def test_min_severity_gating():
    hub = alert_hub(min_severity="critical")
    hub.maybe_dispatch(_exploit_capture())  # command_parameter signal is medium, gate is critical
    assert hub._tasks == set()


def test_delivery_success_and_failure_accounting():
    hub = alert_hub(min_severity="low", cooldown_seconds=0)
    client = _FakeClient([204, RuntimeError("connection refused")])
    hub._client = client

    async def run():
        hub.maybe_dispatch(_exploit_capture())
        hub.maybe_dispatch(_exploit_capture())
        await asyncio.gather(*list(hub._tasks), return_exceptions=True)
        await hub.close()

    asyncio.run(run())
    assert len(client.posted) == 2
    url, payload = client.posted[0]
    assert url == "http://hook.invalid/x"
    assert payload["sensor"] == "phptopwn"
    assert payload["client_ip"]
    assert payload["signals"] == ["command_parameter"]  # this signal carries no CVE
    assert payload["cves"] == []
    json.dumps(payload)  # payload must be JSON-serializable
    assert hub.metrics.counters["alerts_sent"] == 1
    assert hub.metrics.counters["alerts_failed"] == 1
    assert client.closed is True


def test_ioc_hints_and_metering_payload_shape():
    hub = alert_hub(min_severity="low")
    client = _FakeClient([204])
    hub._client = client

    async def run():
        hub.maybe_dispatch(_exploit_capture())
        await asyncio.gather(*list(hub._tasks), return_exceptions=True)
        await hub.close()

    asyncio.run(run())
    payload = client.posted[0][1]
    for key in ("request_id", "timestamp", "method", "path", "severity"):
        assert key in payload, key


def test_cooldown_meters_repeats_then_expires():
    hub = alert_hub(min_severity="low", cooldown_seconds=60.0)
    client = _FakeClient([204, 204])
    hub._client = client

    async def run():
        first = _exploit_capture()
        hub.maybe_dispatch(first)
        await asyncio.gather(*list(hub._tasks), return_exceptions=True)

        hub.maybe_dispatch(_exploit_capture())  # still inside the window -> metered
        assert len(client.posted) == 1
        assert hub.metrics.counters["alerts_metered"] == 1

        del hub._cooldown[first.client_ip]  # expire the window manually
        hub.maybe_dispatch(_exploit_capture())
        await asyncio.gather(*list(hub._tasks), return_exceptions=True)
        await hub.close()

    asyncio.run(run())
    assert len(client.posted) == 2


class _BlockedClient:
    """Delivery hangs briefly, to exercise the inflight cap."""

    def __init__(self):
        self.posted = 0

    async def post(self, url, json=None, **kwargs):
        await asyncio.sleep(0.25)
        self.posted += 1
        return SimpleNamespace(status_code=204)

    async def aclose(self):
        return None


def test_max_inflight_overflow():
    hub = alert_hub(max_inflight=1, cooldown_seconds=0, min_severity="low")
    hub._client = _BlockedClient()

    async def run():
        hub.maybe_dispatch(_exploit_capture())
        await asyncio.sleep(0.05)  # first delivery is still in flight
        hub.maybe_dispatch(_exploit_capture())
        assert hub.metrics.counters["alerts_overflow"] == 1
        await asyncio.gather(*list(hub._tasks), return_exceptions=True)
        await hub.close()

    asyncio.run(run())
