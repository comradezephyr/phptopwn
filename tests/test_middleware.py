"""ASGI middleware and decoy surface behaviour via the full FastAPI app."""
from __future__ import annotations

import json

import pytest
from conftest import make_cfg, multipart_body
from starlette.testclient import TestClient

from phptopwn.decoy import create_app
from phptopwn.middleware import TelemetryMiddleware
from phptopwn.runtime import Sensor
from phptopwn.storage import ArtifactStore

SHELL = b"<?php system($_GET['c']); ?>"


@pytest.fixture()
def harness(tmp_path):
    def build(**overrides):
        cfg = make_cfg(tmp_path, **overrides)
        sensor = Sensor(cfg)
        sensor.store = ArtifactStore(cfg)
        app = create_app(cfg, sensor)
        return TestClient(app), sensor, cfg, sensor.store

    return build


def _latest_record(store: ArtifactStore) -> dict:
    lines = store.log_path.read_text(encoding="utf-8").strip().splitlines()
    return json.loads(lines[-1])


def test_tunnel_client_ip_resolution(harness):
    client, _, _, store = harness(
        client_ip_header="CF-Connecting-IP", header_count=33, header_bytes=16384
    )
    ok = client.post(
        "/upload.php",
        data=b"name=quarterly-report&note=benign",
        headers={
            "Content-Type": "application/x-www-form-urlencoded",
            "CF-Connecting-IP": "198.51.100.9",
            "X-Forwarded-For": "10.0.0.99",
        },
    )
    assert ok.status_code == 200
    record = _latest_record(store)
    assert record["client"]["ip"] == "198.51.100.9"  # CF header wins over XFF
    assert record["client"]["peer_ip"] == "testclient"
    assert record["client"]["peer_ip"] != record["client"]["ip"]


def test_tunnel_without_header_falls_back_to_raw_peer(harness):
    client, _, _, store = harness(
        client_ip_header="CF-Connecting-IP", header_count=33, header_bytes=16384
    )
    ok = client.post(
        "/upload.php",
        data=b"name=note&note=benign",
        headers={"Content-Type": "application/x-www-form-urlencoded"},
    )
    assert ok.status_code == 200
    record = _latest_record(store)
    assert record["client"]["ip"] == "testclient"
    assert record["client"]["peer_ip"] == "testclient"


def test_guard_uses_effective_ip_not_tunnel_peer(harness):
    client, _, _, _ = harness(
        client_ip_header="CF-Connecting-IP",
        rate_limit_per_minute=1,
        header_count=33,
        header_bytes=16384,
    )
    for ip in ("198.51.100.9", "198.51.100.10"):
        ok = client.post(
            "/upload.php",
            data=b"a=1&note=benign",
            headers={
                "Content-Type": "application/x-www-form-urlencoded",
                "CF-Connecting-IP": ip,
            },
        )
        assert ok.status_code == 200
    third = client.post(
        "/upload.php",
        data=b"a=2&note=benign",
        headers={
            "Content-Type": "application/x-www-form-urlencoded",
            "CF-Connecting-IP": "198.51.100.9",
        },
    )
    assert third.status_code == 403
    distinct = client.post(
        "/upload.php",
        data=b"a=3&note=benign",
        headers={
            "Content-Type": "application/x-www-form-urlencoded",
            "CF-Connecting-IP": "198.51.100.11",
        },
    )
    assert distinct.status_code == 200


def test_decoy_index_fingerprints(harness):
    client, _, _, _ = harness()
    response = client.get("/")
    assert response.status_code == 200
    assert response.headers["server"] == "Apache/2.4.52 (Ubuntu)"
    assert response.headers["x-powered-by"] == "PHP/8.1.2"
    assert "Intranet File Portal" in response.text
    assert response.headers["x-request-id"]


def test_benign_upload_unknown_routes_and_head(harness):
    client, _, _, _ = harness()
    ok = client.post(
        "/upload.php",
        data=b"name=quarterly-report&note=benign",
        headers={"Content-Type": "application/x-www-form-urlencoded"},
    )
    assert ok.status_code == 200
    assert "Upload complete" in ok.text

    missing = client.get("/no-such-page")
    assert missing.status_code == 404 and b"Not Found" in missing.content

    assert client.get("/healthz").status_code == 404  # decoy exposes no ops route

    head = client.head("/")
    assert head.status_code == 200 and head.content == b""
    assert int(head.headers["content-length"]) > 0


def test_static_decoy_routes(harness):
    client, _, _, _ = harness()
    assert "session.upload_progress.enabled" in client.get("/phpinfo.php").text
    assert "Index of /uploads" in client.get("/uploads").text
    assert "Server Version" in client.get("/server-status").text
    assert "Disallow: /uploads/" in client.get("/robots.txt").text

    login = client.get("/wp-login.php")
    assert "Password" in login.text
    failed = client.post("/wp-login.php", data={"log": "root", "pwd": "hunter2"})
    assert "Error:" in failed.text and "incorrect" in failed.text


def test_poisoning_upload_is_simulated_and_recorded(harness):
    client, _, _, store = harness()
    body, boundary = multipart_body(
        [
            {"name": "PHP_SESSION_UPLOAD_PROGRESS", "data": "race"},
            {"name": "file", "filename": "shell.php", "content_type": "application/x-php", "data": SHELL},
        ]
    )
    response = client.post(
        "/upload.php",
        content=body,
        headers={"Content-Type": f"multipart/form-data; boundary={boundary}"},
    )
    assert response.status_code == 200
    assert "session.upload_progress" in response.text

    records = [json.loads(line) for line in store.log_path.read_text().splitlines()]
    exploit = [record for record in records if record["analysis"]["is_exploit"]]
    assert exploit, "poisoning upload was not logged as an exploit"
    assert "CVE-2026-109619" in exploit[0]["analysis"]["cves"]


def test_oom_bait_returns_php_fatal(harness):
    client, _, _, store = harness()
    body, boundary = multipart_body([{"name": "blob", "data": "A" * 3000}])
    response = client.post(
        "/upload.php",
        content=body,
        headers={"Content-Type": f"multipart/form-data; boundary={boundary}"},
    )
    assert response.status_code == 500
    assert "Allowed memory size" in response.text

    records = [json.loads(line) for line in store.log_path.read_text().splitlines()]
    assert any(record["response"]["status"] == 500 for record in records)
    assert any("CVE-2026-109618" in record["analysis"]["cves"] for record in records)


def test_rate_limit_guard_rejects(harness):
    client, sensor, _, _ = harness(RATE_LIMIT_PER_MINUTE="1")
    assert client.get("/").status_code == 200
    refused = client.get("/")
    assert refused.status_code == 403
    assert b"403 Forbidden" in refused.content
    assert sensor.metrics.counters["rate_limited"] == 1


def test_header_flood_rejected(harness):
    client, sensor, _, _ = harness(MAX_REQUEST_HEADERS="8")
    headers = {f"X-Flood-{i}": "excessive" for i in range(12)}
    response = client.get("/", headers=headers)
    assert response.status_code == 400
    assert b"400 Bad Request" in response.content
    assert sensor.metrics.counters["header_flood"] == 1


def test_guard_rejection_is_persisted(harness):
    client, _, _, store = harness(RATE_LIMIT_PER_MINUTE="1")
    client.get("/")
    client.get("/")
    records = [json.loads(line) for line in store.log_path.read_text().splitlines()]
    guards = [record for record in records if record.get("error") == "rate_limited"]
    assert guards, "guard rejection was not persisted"
    assert guards[0]["body"]["bytes"] == 0
    assert guards[0]["client"]["ip"] == "testclient"


def test_capture_reaches_inner_app_and_persistence(harness):
    client, sensor, cfg, store = harness()

    responder_calls: list = []

    async def responder(scope, receive, send):
        capture = scope.get("phptopwn.capture")
        responder_calls.append(capture)
        await send(
            {
                "type": "http.response.start",
                "status": 200,
                "headers": [(b"content-type", b"text/plain; charset=utf-8")],
            }
        )
        await send({"type": "http.response.body", "body": b"seen"})

    app = TelemetryMiddleware(responder, cfg, sensor)
    plain = TestClient(app)
    response = plain.post(
        "/upload.php",
        content=b"x=1",
        headers={"Content-Type": "application/x-www-form-urlencoded"},
    )
    assert response.status_code == 200
    assert response.text == "seen"
    assert response.headers["server"] == "Apache/2.4.52 (Ubuntu)"
    capture = responder_calls[0]
    assert capture is not None
    assert capture.path == "/upload.php"
    assert capture.form == {"x": "1"}
    assert capture.analysis is not None and capture.analysis.is_exploit is False

    records = [json.loads(line) for line in store.log_path.read_text().splitlines()]
    assert any(record["request_id"] == capture.request_id for record in records)


def test_decoy_500_from_broken_handler(harness):
    client, _, cfg, store = harness()

    async def broken(scope, receive, send):
        raise RuntimeError("simulated handler crash")

    app = TelemetryMiddleware(broken, cfg, Sensor(cfg))
    plain = TestClient(app, raise_server_exceptions=False)
    response = plain.post("/", content=b"")
    assert response.status_code == 500
    assert b"Internal Server Error" in response.content
