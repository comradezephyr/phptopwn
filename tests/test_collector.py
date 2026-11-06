"""Collector: config loading, event validation, store dedupe, ingest, IOC export."""
from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from starlette.testclient import TestClient

from phptopwn.collector import (
    CollectConfig,
    CollectConfigError,
    EventStore,
    IngestGuard,
    create_collector_app,
    day_of,
    read_collect_config,
    validate_event,
)
from phptopwn.collector_cli import main as cli_main
from phptopwn.ioc import aggregate_day, export_day

NOW = datetime.now(UTC)
TODAY = NOW.strftime("%Y-%m-%d")
TODAY_COMPACT = TODAY.replace("-", "")
TOMORROW_COMPACT = (NOW + timedelta(days=1)).strftime("%Y%m%d")
YESTERDAY_COMPACT = (NOW - timedelta(days=1)).strftime("%Y%m%d")
TOKEN = "c" * 40


def collect_cfg(tmp: Path, **overrides: object) -> CollectConfig:
    values: dict[str, object] = {
        "ingest_token": TOKEN,
        "data_dir": tmp / "collector-data",
        "max_event_bytes": 262144,
        "max_batch_bytes": 1048576,
    }
    values.update(overrides)
    return CollectConfig(**values)


def collect_config_toml(tmp: Path, extra: str = "") -> Path:
    path = tmp / "collect.toml"
    path.write_text(
        "[collector]\n"
        f'ingest_token = "{TOKEN}"\n'
        f'data_dir = "{tmp / "collector-data"}"\n'
        + extra
        + "\n[nodes]\n"
        'sensor-a = "eu-west"\n'
        'lab-asia-1 = "south-asia"\n',
        encoding="utf-8",
    )
    return path


def record(
    i: int = 0,
    *,
    request_id: str | None = None,
    ip: str = "203.0.113.5",
    path: str = "/shell.php",
    method: str = "POST",
    exploit: bool = True,
    ts: str | None = None,
    body_hash: str | None = None,
    body_bytes: int = 16,
    artifacts: list[dict] | None = None,
    schema: str = "phptopwn.event/1.0",
    day: str = TODAY,
) -> dict:
    if ts is None:
        ts = f"{day}T10:{(i // 60) % 60:02d}:{i % 60:02d}Z"
    return {
        "schema": schema,
        "event": "http_request",
        "request_id": request_id or f"task-{i}",
        "timestamp": ts,
        "client": {"ip": ip, "port": 40000 + i},
        "request": {"method": method, "path": path},
        "response": {"status": 404, "bytes": 290},
        "body": {"bytes": body_bytes, "sha256": body_hash or hashlib.sha256(f"p{i}".encode()).hexdigest()},
        "artifacts": artifacts or [],
        "analysis": {"is_exploit": exploit},
    }


def ndjson(*records: dict) -> str:
    return "\n".join(json.dumps(record) for record in records) + "\n"


# --- config loading ------------------------------------------------------------
def test_read_collect_config_valid(tmp_path):
    cfg, node_map = read_collect_config(collect_config_toml(tmp_path))
    assert cfg.ingest_token == TOKEN
    assert cfg.data_dir == tmp_path / "collector-data"
    assert node_map == {"sensor-a": "eu-west", "lab-asia-1": "south-asia"}


def test_read_collect_config_rejects_unknown_key(tmp_path):
    with pytest.raises(CollectConfigError, match="unknown key"):
        read_collect_config(collect_config_toml(tmp_path, extra='wrong_key = 1\n'))


@pytest.mark.parametrize(
    "extra_lines, match",
    [
        ('ingest_token = "short"\n', "ingest_token"),
        ('port = 70000\n', "port"),
        ('dedupe_days = 0\n', "dedupe_days"),
        ('max_event_bytes = 4\n', "max_event_bytes"),
        ("max_batch_bytes = 8192\nmax_event_bytes = 16384\n", "max_batch_bytes"),
    ],
)
def test_read_collect_config_rejects_bad_values(tmp_path, extra_lines, match):
    if "ingest_token" not in extra_lines:
        extra_lines = f'ingest_token = "{TOKEN}"\n' + extra_lines
    path = tmp_path / "collect.toml"
    path.write_text(
        "[collector]\n" + extra_lines + f'data_dir = "{tmp_path / "d"}"\n', encoding="utf-8"
    )
    with pytest.raises(CollectConfigError, match=match):
        read_collect_config(path)


def test_read_collect_config_rejects_bad_nodes(tmp_path):
    path = tmp_path / "collect.toml"
    path.write_text(
        "[collector]\n"
        f'ingest_token = "{TOKEN}"\n'
        f'data_dir = "{tmp_path / "collector-data"}"\n'
        "\n[nodes]\n"
        '"b@d-node" = "eu"\n',
        encoding="utf-8",
    )
    with pytest.raises(CollectConfigError, match="nodes"):
        read_collect_config(path)


# --- event validation ----------------------------------------------------------
def test_validate_event_accepts_minimal():
    value, error = validate_event(json.dumps(record()))
    assert error is None and value is not None
    assert value["request_id"] == "task-0"


@pytest.mark.parametrize(
    "line, reason",
    [
        ("{not json", "invalid_json"),
        ('["a", "b"]', "invalid_json"),
        (json.dumps(record(schema="phptopwn.event/9.9")), "schema_mismatch"),
        (json.dumps({"schema": "phptopwn.event/1.0", "event": "http_request"}), "invalid_shape:request_id"),
        (json.dumps(record(request_id="bad id")), "invalid_shape:request_id"),
        (json.dumps(record(ts="not-a-date")), "invalid_shape:timestamp"),
        (json.dumps(record(ip=123)), "invalid_shape:client.ip"),
        (
            json.dumps(
                {
                    "schema": "phptopwn.event/1.0",
                    "request": {},
                    "request_id": "a",
                    "timestamp": "2026-01-01T00:00:00Z",
                    "client": {"ip": "1.1.1.1"},
                }
            ),
            "invalid_shape:request.method",
        ),
        (json.dumps({"schema": "phptopwn.event/1.0", "event": "nope"}), "invalid_shape:event"),
    ],
)
def test_validate_event_rejects(line, reason):
    value, error = validate_event(line)
    assert value is None and error == reason


def test_day_of():
    assert day_of({"timestamp": "2026-03-04T05:06:07Z"}) == "20260304"


# --- event store ---------------------------------------------------------------
def test_store_dedupe_and_enrichment(tmp_path):
    store = EventStore(collect_cfg(tmp_path), {"s1": "eu"})
    store.open()
    first, second = record(0), record(1)
    accepted, duplicates = store.append("s1", "eu", [first, second, record(0)])
    assert (accepted, duplicates) == (2, 1)
    assert store.available_days() == [TODAY_COMPACT]
    events = list(store.iter_day(TODAY_COMPACT))
    assert len(events) == 2
    first_meta = events[0]["collector"]
    assert first_meta["node"] == "s1"
    assert first_meta["region"] == "eu"
    assert "received_at" in first_meta
    ids_file = tmp_path / "collector-data" / "ids" / f"{TODAY_COMPACT}.ids"
    assert ids_file.read_text(encoding="utf-8").splitlines() == ["task-0", "task-1"]


def test_store_dedupes_across_restart(tmp_path):
    cfg = collect_cfg(tmp_path)
    store = EventStore(cfg, {"s1": "eu"})
    store.open()
    store.append("s1", "eu", [record(0)])
    reopened = EventStore(cfg, {"s1": "eu"})
    reopened.open()
    accepted, duplicates = reopened.append("s1", "eu", [record(0)])
    assert (accepted, duplicates) == (0, 1)
    assert len(list(store.iter_day(TODAY_COMPACT))) == 1


def test_store_dedupe_window_covers_yesterday(tmp_path):
    store = EventStore(collect_cfg(tmp_path), {"s1": "eu"})
    store.open()
    yesterday = record(0, ts=f"{YESTERDAY_COMPACT[:4]}-{YESTERDAY_COMPACT[4:6]}-{YESTERDAY_COMPACT[6:]}T23:00:00Z")
    store.append("s1", "eu", [yesterday])
    assert TODAY_COMPACT not in store.available_days()
    assert YESTERDAY_COMPACT in store.available_days()
    reopened = EventStore(collect_cfg(tmp_path), {})
    reopened.open()
    accepted, duplicates = reopened.append("s1", "eu", [yesterday])
    assert (accepted, duplicates) == (0, 1)


def test_store_summary_and_recent(tmp_path):
    store = EventStore(collect_cfg(tmp_path), {"s1": "eu"})
    store.open()
    store.append("s1", "eu", [record(0), record(1, exploit=False, ip="198.51.100.9")])
    summary = store.summary(TODAY_COMPACT)
    assert summary["totals"] == {"events": 2, "exploits": 1, "benign": 1}
    assert summary["regions"] == {"eu": {"events": 2, "exploits": 1}}
    assert summary["nodes"] == {"s1": {"events": 2, "exploits": 1}}
    assert summary["unique_ips"] == 2
    assert store.recent(1)[0]["request_id"] == "task-1"
    assert [r["request_id"] for r in store.recent(10)] == ["task-1", "task-0"]


# --- ingest guard --------------------------------------------------------------
def test_ingest_guard_rolling_window():
    guard = IngestGuard(limit_per_minute=2)
    assert guard.allow("1.2.3.4")
    assert guard.allow("1.2.3.4")
    assert not guard.allow("1.2.3.4")
    assert guard.allow("5.6.7.8")


def test_ingest_guard_disabled():
    guard = IngestGuard(limit_per_minute=0)
    assert all(guard.allow("1.2.3.4") for _ in range(50))


def test_ingest_guard_evicts_oldest_ip_at_capacity():
    guard = IngestGuard(limit_per_minute=1, capacity=2)
    assert guard.allow("a")
    assert guard.allow("b")
    assert len(guard._events) == 2
    assert guard.allow("c")
    assert len(guard._events) == 2
    assert "a" not in guard._events


# --- ingest endpoint -----------------------------------------------------------
def _client(tmp_path, **cfg_overrides):
    cfg = collect_cfg(tmp_path, **cfg_overrides)
    store = EventStore(cfg, {"s1": "eu-west"})
    store.open()
    app = create_collector_app(cfg, store)
    return TestClient(app), store


def _post(client, body: str, token: str = TOKEN, node: str = "s1", ct: str = "application/x-ndjson"):
    return client.post(
        "/v1/events",
        content=body.encode(),
        headers={
            "Authorization": f"Bearer {token}",
            "X-Phptopwn-Node": node,
            "Content-Type": ct,
        },
    )


def test_ingest_auth_required(tmp_path):
    client, _ = _client(tmp_path)
    assert _post(client, ndjson(record()), token="w" * 40).status_code == 401
    bare = client.post(
        "/v1/events",
        content=ndjson(record()).encode(),
        headers={"X-Phptopwn-Node": "s1", "Content-Type": "application/x-ndjson"},
    )
    assert bare.status_code == 401


def test_ingest_unknown_node(tmp_path):
    client, _ = _client(tmp_path)
    assert _post(client, ndjson(record()), node="mystery").status_code == 403


def test_ingest_rejects_no_ndjson_content_type(tmp_path):
    client, _ = _client(tmp_path)
    assert _post(client, ndjson(record()), ct="application/json").status_code == 415


def test_ingest_accepts_and_dedupes(tmp_path):
    client, store = _client(tmp_path)
    body = ndjson(record(0), record(1))
    response = _post(client, body)
    assert response.status_code == 200
    report = response.json()
    assert report["accepted"] == 2 and report["duplicates"] == 0
    assert report["rejected"] == {}
    second = _post(client, body)
    assert second.json()["accepted"] == 0 and second.json()["duplicates"] == 2
    assert len(list(store.iter_day(TODAY_COMPACT))) == 2


def test_ingest_reports_bad_lines_without_failing_batch(tmp_path):
    client, store = _client(tmp_path)
    body = (
        ndjson(record(0))
        + "\n"
        + "{not json}\n"
        + ndjson(record(1, schema="phptopwn.event/9.9"))
    )
    response = _post(client, body)
    assert response.status_code == 200
    report = response.json()
    assert report["accepted"] == 1
    assert report["rejected"] == {"blank": 1, "invalid_json": 1, "schema_mismatch": 1}
    assert report["total"] == 4
    assert len(list(store.iter_day(TODAY_COMPACT))) == 1


def test_ingest_rejects_oversized_line(tmp_path):
    client, store = _client(tmp_path)
    pad = "a" * (300 * 1024)
    big = record(0)
    big["pad"] = pad
    response = _post(client, ndjson(big, record(1)))
    assert response.status_code == 200
    report = response.json()
    assert report["rejected"]["line_too_large"] == 1
    assert report["accepted"] == 1
    assert len(list(store.iter_day(TODAY_COMPACT))) == 1


def test_ingest_413_batch_events(tmp_path):
    client, _ = _client(tmp_path, max_batch_events=16)
    body = ndjson(*[record(i) for i in range(17)])
    response = _post(client, body)
    assert response.status_code == 413


def test_ingest_413_batch_bytes(tmp_path):
    client, _ = _client(tmp_path, max_event_bytes=16384, max_batch_bytes=32768)
    records = []
    for i in range(3):
        padded = record(i, body_hash=hashlib.sha256(f"q{i}".encode()).hexdigest())
        padded["pad"] = "x" * 12000
        records.append(padded)
    body = ndjson(*records)
    assert len(body) > 32768
    assert _post(client, body).status_code == 413


def test_ingest_429_rate_limited(tmp_path):
    cfg = collect_cfg(tmp_path, ingest_rate_per_minute=1)
    store = EventStore(cfg, {"s1": "eu-west"})
    store.open()
    client = TestClient(create_collector_app(cfg, store))
    assert _post(client, ndjson(record(0))).status_code == 200
    assert _post(client, ndjson(record(1))).status_code == 429


def test_ingest_security_headers(tmp_path):
    client, _ = _client(tmp_path)
    response = _post(client, ndjson(record(0)))
    assert response.headers["x-content-type-options"] == "nosniff"
    assert response.headers["x-frame-options"] == "DENY"
    page = client.get("/")
    assert page.headers["content-security-policy"].startswith("default-src 'none'")


def test_healthz_reports_counters(tmp_path):
    client, _ = _client(tmp_path)
    _post(client, ndjson(record(0), record(0)))
    report = client.get("/healthz").json()
    assert report["status"] == "ok"
    assert report["stats"]["events_accepted"] == 1
    assert report["stats"]["events_duplicates"] == 1
    assert TODAY_COMPACT in report["recent_days"]


def test_dashboard_pages(tmp_path):
    client, _ = _client(tmp_path)
    _post(client, ndjson(record(0), record(1, exploit=False)))
    overview = client.get("/")
    assert overview.status_code == 200
    assert "<table>" in overview.text and TODAY_COMPACT in overview.text
    regions = client.get("/regions")
    assert regions.status_code == 200 and "eu-west" in regions.text
    events = client.get("/events", params={"limit": 5})
    assert events.status_code == 200 and "/shell.php" in events.text
    assert client.get("/events", params={"limit": 9999}).status_code == 200


def test_dashboard_disabled(tmp_path):
    client, _ = _client(tmp_path, dashboard=False)
    assert client.get("/").status_code == 404
    assert client.get("/regions").status_code == 404
    assert client.get("/events").status_code == 404


# --- IOC export ----------------------------------------------------------------
def _store_two_events(tmp_path):
    store = EventStore(collect_cfg(tmp_path), {"s1": "eu-west"})
    store.open()
    body_hash = hashlib.sha256(b"evil-payload").hexdigest()
    uploaded_hash = hashlib.sha256(b"uploaded-shell").hexdigest()
    events = [
        record(0, ip="198.51.100.7", exploit=True, body_hash=body_hash, body_bytes=12),
        record(
            1,
            ip="198.51.100.7",
            exploit=False,
            artifacts=[{"kind": "uploaded_file", "sha256": uploaded_hash, "saved_as": "x.bin"}],
        ),
    ]
    store.append("s1", "eu-west", events)
    return store, body_hash, uploaded_hash


def test_aggregate_day(tmp_path):
    store, body_hash, uploaded_hash = _store_two_events(tmp_path)
    aggregate = aggregate_day(store, TODAY_COMPACT)
    assert aggregate["schema"] == "phptopwn.ioc/1.0"
    assert aggregate["totals"] == {"events": 2, "exploits": 1}
    assert len(aggregate["ips"]) == 1
    entry = aggregate["ips"][0]
    assert entry["value"] == "198.51.100.7"
    assert entry["events"] == 2 and entry["exploits"] == 1
    assert entry["regions"] == ["eu-west"] and entry["first_seen"] < entry["last_seen"]
    hashes = [h["value"] for h in aggregate["payload_hashes"]]
    assert body_hash in hashes and uploaded_hash in hashes


def test_aggregate_day_empty_is_valid(tmp_path):
    store = EventStore(collect_cfg(tmp_path), {})
    store.open()
    aggregate = aggregate_day(store, TOMORROW_COMPACT)
    assert aggregate["totals"] == {"events": 0, "exploits": 0}
    assert aggregate["ips"] == []


def test_export_day_writes_artefacts_and_verifies(tmp_path):
    store, _, _ = _store_two_events(tmp_path)
    out = tmp_path / "export"
    report = export_day(store, TODAY_COMPACT, out)
    assert report["status"] == "exported"
    json_path = out / f"ioc-{TODAY_COMPACT}.json"
    csv_path = out / f"ioc-{TODAY_COMPACT}.csv"
    manifest_path = out / f"ioc-{TODAY_COMPACT}.manifest.json"
    for path in (json_path, csv_path, manifest_path):
        assert path.exists()
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    for name, digest in manifest["files"].items():
        assert hashlib.sha256((out / name).read_bytes()).hexdigest() == digest
    assert manifest["counts"]["ips"] == 1
    csv_text = csv_path.read_text(encoding="utf-8")
    lines = csv_text.strip().splitlines()
    assert lines[0] == "type,value,first_seen,last_seen,events,exploits,regions"
    assert any("198.51.100.7" in line for line in lines[1:])


def test_export_day_refuses_overwrite_then_forces(tmp_path):
    store, _, _ = _store_two_events(tmp_path)
    out = tmp_path / "export"
    assert export_day(store, TODAY_COMPACT, out, force=False)["status"] == "exported"
    refused = export_day(store, TODAY_COMPACT, out, force=False)
    assert refused["status"] == "refused" and refused["refused"]
    forced = export_day(store, TODAY_COMPACT, out, force=True)
    assert forced["status"] == "exported"


# --- CLI -----------------------------------------------------------------------
def test_cli_invalid_config_exits(tmp_path):
    bad = tmp_path / "collect.toml"
    bad.write_text("[collector]\ningest_token = \"x\"\n", encoding="utf-8")
    assert cli_main(["serve", "--config", str(bad)]) == 2


def test_cli_day_format_checked(tmp_path):
    cfg_path = collect_config_toml(tmp_path)
    assert cli_main(["ioc", "--day", "abcd", "--config", str(cfg_path), "--out", str(tmp_path)]) == 2
    assert cli_main(["ioc", "--day", "2026011", "--config", str(cfg_path), "--out", str(tmp_path)]) == 2


def test_cli_ioc_missing_day(tmp_path):
    cfg_path = collect_config_toml(tmp_path)
    assert cli_main(["ioc", "--day", "19990101", "--config", str(cfg_path), "--out", str(tmp_path / "e")]) == 2


def test_cli_ioc_export_and_refusal(tmp_path):
    store, _, _ = _store_two_events(tmp_path)
    del store
    out = tmp_path / "cli-out"
    cfg_path = collect_config_toml(tmp_path)
    assert cli_main(["ioc", "--day", TODAY_COMPACT, "--config", str(cfg_path), "--out", str(out)]) == 0
    assert (out / f"ioc-{TODAY_COMPACT}.json").exists()
    assert cli_main(["ioc", "--day", TODAY_COMPACT, "--config", str(cfg_path), "--out", str(out)]) == 1
    assert cli_main(["ioc", "--day", TODAY_COMPACT, "--config", str(cfg_path), "--out", str(out), "--force"]) == 0


def test_cli_serve_preflight_proxy_invocation(tmp_path, monkeypatch):
    captured: dict = {}

    def fake_run(**options):
        captured["options"] = options

    import uvicorn

    monkeypatch.setattr(uvicorn, "run", fake_run)
    serve_cfg_path = collect_config_toml(tmp_path)
    assert cli_main(["serve", "--config", str(serve_cfg_path), "--host", "127.0.0.1", "--port", "9443"]) == 0
    assert captured["options"]["host"] == "127.0.0.1"
    assert captured["options"]["port"] == 9443
    assert "app" in captured["options"]


def test_cli_serve_missing_cert(tmp_path):
    sub = tmp_path / "sub"
    sub.mkdir(parents=True)
    tls_extra = (
        f'tls_enabled = true\ncert_file = "{sub / "no.crt"}"\n'
        f'key_file = "{sub / "no.key"}"\n'
    )
    cfg_path = collect_config_toml(sub, extra=tls_extra)
    assert cli_main(["serve", "--config", str(cfg_path)]) == 2
