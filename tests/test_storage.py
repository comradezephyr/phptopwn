"""Telemetry persistence: records, quarantine, IOC feed, retention sweeps."""
from __future__ import annotations

import asyncio
import json
import os
import time
from dataclasses import replace as dc_replace

from conftest import build_capture, make_cfg, multipart_body

from phptopwn.capture import MultipartPart
from phptopwn.detection import analyze
from phptopwn.parsing import enrich_capture
from phptopwn.storage import (
    ArtifactStore,
    body_extension,
    build_record,
    clean_text,
    part_extension,
    retention_sweep,
    rotate_file,
)

SHELL = b"<?php system($_GET['c']); ?>"


def _classified(body: bytes, headers: dict[str, str]):
    capture = build_capture(body=body, headers=headers)
    enrich_capture(capture)
    capture.analysis = analyze(capture, make_cfg())
    return capture


def _exploit_capture():
    body, boundary = multipart_body(
        [
            {"name": "PHP_SESSION_UPLOAD_PROGRESS", "data": "race"},
            {"name": "file", "filename": "shell.php", "content_type": "application/x-php", "data": SHELL},
        ]
    )
    return _classified(body, {"Content-Type": f"multipart/form-data; boundary={boundary}"})


def _persist(store: ArtifactStore, capture) -> None:
    asyncio.run(store.persist(capture))


def test_clean_text_replaces_controls_and_caps():
    assert clean_text("a\x00b\x1fc", 16) == "a\ufffdb\ufffdc"
    assert clean_text("x" * 40, 10) == "x" * 10
    assert clean_text(None, 4) == "None"


def _part(filename="shell.php", content_type="application/x-php"):
    return MultipartPart(
        index=0, name="f", filename=filename, content_type=content_type,
        headers={}, header_size=0, size=1, sha256="0" * 64, data=b"x",
    )


def test_part_extension_follows_neutralization_rule():
    assert part_extension(_part(), neutralize=True) == ".bin"
    assert part_extension(_part(), neutralize=False) == ".php"

    script = _part(filename="drip.sh", content_type="application/x-sh")
    assert part_extension(script, neutralize=False) == ".sh"
    assert part_extension(script, neutralize=True) == ".bin"

    unknown = _part(filename=None, content_type="weird/mime")
    assert part_extension(unknown, neutralize=False) == ".bin"


def test_body_extension_types():
    capture = build_capture(headers={"Content-Type": "application/x-php"})
    assert body_extension(capture) == ".bin"
    capture = build_capture(headers={"Content-Type": "multipart/form-data; boundary=x"})
    assert body_extension(capture) == ".multipart"
    capture = build_capture(
        body=b"a=1", headers={"Content-Type": "application/x-www-form-urlencoded"}
    )
    assert body_extension(capture) == ".form"
    assert body_extension(build_capture(headers={"Content-Type": "text/plain"})) == ".txt"
    assert body_extension(build_capture(headers={"Content-Type": "weird/mime"})) == ".body"


def test_build_record_shape_is_complete():
    capture = build_capture(
        body=b"abc",
        path="/upload.php?q=1",
        query="q=1",
        headers={"Content-Type": "text/plain", "User-Agent": "probe/1"},
        chunk_gaps=[0.01],
    )
    record = build_record(capture, make_cfg())
    assert record["schema"] == "phptopwn.event/1.0"
    assert {"name", "version", "server_token", "powered_by"} <= set(record["sensor"])
    assert {"ip", "port"} <= set(record["client"])
    assert {"method", "path", "headers"} <= set(record["request"])
    assert {"bytes", "sha256", "preview", "saved_as"} <= set(record["body"])
    assert record["body"]["sha256"] == capture.body_sha256
    assert record["body"]["saved_as"] is None
    assert record["artifacts"] == []
    assert record["error"] is None


def test_store_open_creates_layout(tmp_path):
    store = ArtifactStore(make_cfg(tmp_path))
    store.open()
    assert store.log_path.exists()
    assert store.ioc_path.read_text().startswith("# phptopwn IOC feed")
    assert store.manifest_path.exists()


def test_persist_benign_logged_when_log_all(tmp_path):
    cfg = make_cfg(tmp_path, LOG_ALL="true")
    store = ArtifactStore(cfg)
    capture = build_capture(body=b"note=benign", headers={"Content-Type": "application/x-www-form-urlencoded"})
    _persist(store, capture)
    records = [json.loads(line) for line in store.log_path.read_text().splitlines()]
    assert records and records[0]["request"]["path"] == "/upload.php"
    assert records[0]["analysis"]["is_exploit"] is False
    assert list(cfg.storage.capture_dir.iterdir()) == [store.manifest_path]


def test_persist_exploit_saves_artifacts_and_iocs(tmp_path):
    cfg = make_cfg(tmp_path, LOG_ALL="false")
    store = ArtifactStore(cfg)
    capture = _exploit_capture()

    _persist(store, capture)
    records = [json.loads(line) for line in store.log_path.read_text().splitlines()]
    assert len(records) == 1
    record = records[0]
    assert record["analysis"]["is_exploit"] is True
    artifact_kinds = {entry["kind"] for entry in record["artifacts"]}
    assert artifact_kinds == {"request_body", "uploaded_file"}

    body_file = cfg.storage.capture_dir / record["body"]["saved_as"]
    assert body_file.read_bytes() == capture.body_probe
    assert body_file.name.endswith(".multipart")

    uploaded = next(entry for entry in record["artifacts"] if entry["kind"] == "uploaded_file")
    assert uploaded["original_filename"] == "shell.php"
    tamed = cfg.storage.capture_dir / uploaded["file"]
    assert tamed.read_bytes() == SHELL
    assert tamed.name.endswith(".bin")  # never stored as .php

    manifest = [
        json.loads(line)
        for line in (cfg.storage.capture_dir / "manifest.jsonl").read_text().splitlines()
    ]
    assert {entry["file"] for entry in manifest} >= {record["body"]["saved_as"], uploaded["file"]}
    assert all({"sha256", "request_id", "first_seen"} <= set(entry) for entry in manifest)

    entries = [
        line.split("\t")
        for line in store.ioc_path.read_text().splitlines()
        if line and not line.startswith("#")
    ]
    assert any(entry[0] == "ip" for entry in entries)
    assert any(entry[0] == "sha256" for entry in entries)

    # With log_all=false, benign requests are not logged
    benign = build_capture(body=b"note=quiet", headers={"Content-Type": "application/x-www-form-urlencoded"})
    _persist(store, benign)
    assert len(store.log_path.read_text().splitlines()) == 1


def test_persist_dedupes_known_payload_files(tmp_path):
    store = ArtifactStore(make_cfg(tmp_path))
    _persist(store, _exploit_capture())
    manifest_lines = store.manifest_path.read_text().count("\n")

    replay = _exploit_capture()
    replay.request_id = "different-request"
    _persist(store, replay)
    assert store.manifest_path.read_text().count("\n") == manifest_lines  # identical bytes deduped


def test_retention_by_age_and_count(tmp_path):
    cfg = make_cfg(tmp_path, MAX_CAPTURE_FILES="2", MAX_AGE_DAYS="30")
    capture_dir = cfg.storage.capture_dir
    capture_dir.mkdir(parents=True)
    stale = capture_dir / "stale.bin"
    fresh = capture_dir / "fresh.bin"
    extra = capture_dir / "extra.bin"
    for name in (stale, fresh, extra):
        name.write_bytes(b"x")
    old = time.time() - 40 * 86400
    os.utime(stale, (old, old))

    stats = retention_sweep(cfg.retention, capture_dir, cfg.storage.log_dir)
    assert stats["captures_removed"] == 1
    assert not stale.exists()
    assert fresh.exists() and extra.exists()

    os.utime(extra, (old + 1, old + 1))
    stats = retention_sweep(cfg.retention, capture_dir, cfg.storage.log_dir)
    assert stats["captures_removed"] == 1
    assert not extra.exists() and fresh.exists()


def test_retention_rotates_oversized_logs(tmp_path):
    cfg = make_cfg(tmp_path)
    cfg.storage.log_dir.mkdir(parents=True)
    log_file = cfg.storage.log_dir / "exploits.json"
    log_file.write_text("x" * 600)
    old_archive = cfg.storage.log_dir / "exploits.json.20250101T000000Z"
    old_archive.write_text("old")

    ret_cfg = dc_replace(cfg, retention=dc_replace(cfg.retention, max_log_bytes=100, max_log_archives=1))
    stats = retention_sweep(ret_cfg.retention, ret_cfg.storage.capture_dir, ret_cfg.storage.log_dir)
    assert stats["logs_rotated"] == 1
    assert log_file.exists() and log_file.stat().st_size == 0
    archives = sorted(cfg.storage.log_dir.glob("exploits.json.2*"))
    # rotation archives the log once, pruning keeps only the NEWEST archive:
    # the stale 2025 archive is the oldest and gets removed
    assert len(archives) == 1 and old_archive not in archives
    assert archives[0].name != "exploits.json.20250101T000000Z"


def test_rotate_file_lifecycle(tmp_path):
    path = tmp_path / "feed.txt"
    assert rotate_file(path, 3) is False  # missing file
    path.write_text("")
    assert rotate_file(path, 3) is False  # empty file

    path.write_text("payload")
    assert rotate_file(path, 3) is True
    assert not path.exists()
    assert len(list(tmp_path.glob("feed.txt.2*"))) == 1

    path.write_text("payload2")
    assert rotate_file(path, 0) is True  # zero archives means drop history
    assert not list(tmp_path.glob("feed.txt.2*"))
    assert not path.exists()


def test_ioc_keys_loaded_from_existing_feed(tmp_path):
    cfg = make_cfg(tmp_path)
    cfg.storage.log_dir.mkdir(parents=True)
    cfg.storage.capture_dir.mkdir(parents=True)
    (cfg.storage.log_dir / "iocs.txt").write_text("# header\nip\t1.2.3.4\tts\tts\tctx\n")
    (cfg.storage.log_dir / "exploits.json").touch()
    (cfg.storage.capture_dir / "manifest.jsonl").touch()

    store = ArtifactStore(cfg)
    store.open()
    assert ("ip", "1.2.3.4") in store._ioc_keys
