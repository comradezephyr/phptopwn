"""Telemetry persistence: JSONL events, quarantine, IOC feed, retention.

Captured bytes are quarantined as inert files named only by SHA-256. By default
the extension is neutralized (``.bin``) so an operator cannot accidentally mount
``capture_dir`` into a live web root or PHP session path and serve executables.
"""
from __future__ import annotations

import asyncio
import json
import os
import re
import time
from collections import OrderedDict
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from uuid import uuid4

from .capture import Analysis, MultipartPart, RequestCapture
from .config import Config, RetentionConfig
from .parsing import find_webshell_markers, parse_content_type

SENSOR_VERSION = "1.0.0"
CONTROL_CHARS = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")
_IOC_CAPACITY = 200_000

IOC_HEADER = (
    "# phptopwn IOC feed (tab separated)\n"
    "# type\tvalue\tfirst_seen\tlast_seen\tcontext\n"
    "# Blocklist: awk -F'\\t' '!/^#/ && $1==\"ip\" {print $2}' logs/iocs.txt\n"
)

_RECORD_SCHEMA = "phptopwn.event/1.0"

_MIME_EXT = {
    "application/x-php": ".bin",
    "application/x-httpd-php": ".bin",
    "application/x-sh": ".sh",
    "application/javascript": ".js",
    "text/x-python": ".py",
    "application/x-python": ".py",
    "text/plain": ".txt",
}


def utc_now() -> str:
    return datetime.now(UTC).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def clean_text(value: Any, cap: int) -> str:
    """Strip control characters and cap length to keep logs and feeds inject-safe."""
    text = CONTROL_CHARS.sub("\ufffd", str(value))
    return text[:cap]


def part_extension(part: MultipartPart, neutralize: bool) -> str:
    if neutralize:
        return ".bin"
    filename = (part.filename or "").lower()
    for suffix in (".php", ".phtml", ".php5", ".php7", ".phar", ".pht"):
        if filename.endswith(suffix):
            return ".php"
    for suffix in (".sh", ".bash", ".py", ".pl", ".js", ".txt", ".html", ".htm", ".bin"):
        if filename.endswith(suffix):
            return suffix
    if part.content_type:
        extension = _MIME_EXT.get(part.content_type.split(";", 1)[0].strip().lower())
        if extension:
            return extension
    return ".bin"


def body_extension(capture: RequestCapture) -> str:
    mime, _ = parse_content_type(capture.content_type)
    if mime == "multipart/form-data":
        return ".multipart"
    if mime == "application/x-www-form-urlencoded":
        return ".form"
    return _MIME_EXT.get(mime, ".body")


def build_record(capture: RequestCapture, cfg: Config) -> dict[str, Any]:
    analysis = capture.analysis or Analysis()
    return {
        "schema": _RECORD_SCHEMA,
        "event": "http_request",
        "request_id": capture.request_id,
        "timestamp": capture.timestamp,
        "tls": capture.tls,
        "sensor": {
            "name": cfg.decoy.server_name,
            "version": SENSOR_VERSION,
            "server_token": cfg.decoy.server_token,
            "powered_by": cfg.decoy.powered_by,
        },
        "client": {
            "ip": capture.client_ip,
            "port": capture.client_port,
        },
        "request": {
            "method": clean_text(capture.method, 16),
            "scheme": clean_text(capture.scheme, 16),
            "host": clean_text(capture.host, 255),
            "path": clean_text(capture.path, 2048),
            "raw_path": clean_text(capture.raw_path, 2048),
            "query": clean_text(capture.query, 8192),
            "http_version": clean_text(capture.http_version, 16),
            "headers": [
                [clean_text(name, 256), clean_text(value, 4096)]
                for name, value in capture.headers[:128]
            ],
            "header_count": capture.header_count,
            "header_bytes": capture.header_bytes,
            "duplicate_headers": capture.duplicate_headers,
            "content_type": clean_text(capture.content_type, 512),
            "declared_content_length": capture.declared_content_length,
            "transfer_encoding": clean_text(capture.transfer_encoding, 256),
        },
        "body": {
            "bytes": capture.body_size,
            "stored_bytes": capture.body.stored_bytes,
            "sha256": capture.body_sha256,
            "truncated": capture.body.truncated,
            "incomplete": capture.incomplete,
            "disconnected": capture.disconnected,
            "timed_out": capture.timed_out,
            "chunk_count": capture.chunk_count,
            "chunk_gaps_seconds": capture.chunk_gaps[:50],
            "max_chunk_gap_seconds": round(capture.max_chunk_gap, 4),
            "first_byte_seconds": round(capture.first_byte_seconds, 4),
            "total_seconds": round(capture.body_seconds, 4),
            "preview": capture.body_probe[:2048].decode("utf-8", "replace"),
            "saved_as": None,
        },
        "multipart": capture.multipart.to_dict() if capture.multipart else None,
        "form": {
            clean_text(key, 256): clean_text(value, 512)
            for key, value in list(capture.form.items())[:20]
        },
        "query": {
            clean_text(key, 256): clean_text(value, 512)
            for key, value in list(capture.query_params.items())[:20]
        },
        "analysis": analysis.to_dict(),
        "artifacts": [],
        "response": {
            "status": capture.status_code,
            "headers": {
                clean_text(name, 128): clean_text(value, 4096)
                for name, value in list(capture.response_headers.items())[:64]
            },
        },
        "error": clean_text(capture.error, 2048) if capture.error else None,
    }


def _atomic_write(path: Path, writer: Any) -> None:
    """Write via a same-directory temp file, then rename over the destination."""
    tmp_path = path.with_name(f".{path.name}.{os.getpid()}.{uuid4().hex[:8]}.tmp")
    try:
        with tmp_path.open("wb") as handle:
            writer(handle)
        os.replace(tmp_path, path)
    except Exception:
        tmp_path.unlink(missing_ok=True)
        raise


class ArtifactStore:
    """Append-only telemetry, payload quarantine and IOC feed writer."""

    def __init__(self, cfg: Config) -> None:
        self.cfg = cfg
        self.log_path = cfg.storage.log_dir / "exploits.json"
        self.ioc_path = cfg.storage.log_dir / "iocs.txt"
        self.manifest_path = cfg.storage.capture_dir / "manifest.jsonl"
        self._lock = asyncio.Lock()
        self._opened = False
        self._seen_files: set[str] = set()
        self._ioc_keys: OrderedDict[tuple[str, str], None] = OrderedDict()

    def open(self) -> None:
        if self._opened:
            return
        cfg = self.cfg
        for directory in (cfg.storage.log_dir, cfg.storage.capture_dir):
            directory.mkdir(parents=True, exist_ok=True)
        if not self.ioc_path.exists():
            self.ioc_path.write_text(IOC_HEADER, encoding="utf-8")
        self.log_path.touch(exist_ok=True)
        self.manifest_path.touch(exist_ok=True)
        self._load_ioc_keys()
        self._opened = True

    def _load_ioc_keys(self) -> None:
        if not self.ioc_path.exists():
            return
        try:
            lines = self.ioc_path.read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError:
            return
        for line in lines:
            if not line or line.startswith("#"):
                continue
            columns = line.split("\t")
            if len(columns) >= 2:
                self._ioc_keys[(columns[0], columns[1])] = None
        while len(self._ioc_keys) > _IOC_CAPACITY:
            self._ioc_keys.popitem(last=False)

    async def persist(self, capture: RequestCapture) -> None:
        try:
            async with self._lock:
                await asyncio.to_thread(self._persist_sync, capture)
        except Exception:  # telemetry must never break the response path
            import logging

            logging.getLogger("phptopwn.storage").exception(
                "failed to persist telemetry for %s", capture.request_id
            )
        finally:
            capture.body.close()

    def _persist_sync(self, capture: RequestCapture) -> None:
        self.open()
        analysis = capture.analysis or Analysis()
        record = build_record(capture, self.cfg)

        if analysis.is_exploit:
            record["artifacts"] = self._save_artifacts(capture)
            for artifact in record["artifacts"]:
                if artifact["kind"] == "request_body":
                    record["body"]["saved_as"] = artifact["file"]
                    break

        if analysis.is_exploit or self.cfg.detection.log_all_requests:
            with self.log_path.open("a", encoding="utf-8") as handle:
                handle.write(json.dumps(record, ensure_ascii=False, default=str) + "\n")

        if analysis.is_exploit:
            self._update_iocs(capture, analysis)

    def _save_artifacts(self, capture: RequestCapture) -> list[dict[str, Any]]:
        cfg = self.cfg.storage
        artifacts: list[dict[str, Any]] = []
        used = 0
        if capture.body.stored_bytes:
            filename, written, truncated = self._save_body(capture)
            used += written
            artifacts.append(
                {
                    "file": filename,
                    "kind": "request_body",
                    "sha256": capture.body_sha256,
                    "bytes": written,
                    "truncated": truncated,
                }
            )
        if capture.multipart:
            saved_parts = 0
            for part in capture.multipart.parts:
                if saved_parts >= cfg.max_artifact_parts or used >= cfg.max_artifact_bytes:
                    break
                has_markers = bool(find_webshell_markers(part.data))
                if not part.filename and not has_markers:
                    continue
                if part.size == 0 or not part.data:
                    continue
                data = part.data[: cfg.max_artifact_bytes - used]
                if not data:
                    break
                filename = self._save_part(capture, part, data)
                used += len(data)
                saved_parts += 1
                artifacts.append(
                    {
                        "file": filename,
                        "kind": "uploaded_file" if part.filename else "payload_fragment",
                        "sha256": part.sha256,
                        "bytes": len(data),
                        "original_filename": part.filename,
                        "content_type": part.content_type,
                        "truncated": part.truncated or len(data) < part.size,
                    }
                )
        return artifacts

    def _save_body(self, capture: RequestCapture) -> tuple[str, int, bool]:
        filename = f"{capture.body_sha256}{body_extension(capture)}"
        path = self.cfg.storage.capture_dir / filename
        cap = self.cfg.storage.max_artifact_bytes
        written = min(capture.body.stored_bytes, cap)
        truncated = capture.body.truncated or written < capture.body.stored_bytes
        if filename not in self._seen_files and not path.exists():
            tmp_path = path.with_name(f".{path.name}.{os.getpid()}.{uuid4().hex[:8]}.tmp")
            try:
                written = capture.body.save_to(tmp_path, cap)
                os.replace(tmp_path, path)
                self._append_manifest(
                    {
                        "sha256": capture.body_sha256,
                        "file": filename,
                        "kind": "request_body",
                        "size": written,
                        "truncated": truncated,
                        "first_seen": capture.timestamp,
                        "request_id": capture.request_id,
                        "source_ip": capture.client_ip,
                    }
                )
                self._seen_files.add(filename)
            finally:
                tmp_path.unlink(missing_ok=True)
        return filename, written, truncated

    def _save_part(
        self, capture: RequestCapture, part: MultipartPart, data: bytes
    ) -> str:
        neutralize = self.cfg.storage.neutralize_capture_names
        filename = f"{part.sha256}{part_extension(part, neutralize)}"
        path = self.cfg.storage.capture_dir / filename
        truncated = part.truncated or len(data) < part.size
        if filename not in self._seen_files and not path.exists():
            _atomic_write(path, lambda handle: handle.write(data))
            self._append_manifest(
                {
                    "sha256": part.sha256,
                    "file": filename,
                    "kind": "uploaded_file" if part.filename else "payload_fragment",
                    "size": len(data),
                    "original_filename": clean_text(part.filename or "", 255),
                    "content_type": part.content_type,
                    "truncated": truncated,
                    "first_seen": capture.timestamp,
                    "request_id": capture.request_id,
                    "source_ip": capture.client_ip,
                }
            )
            self._seen_files.add(filename)
        return filename

    def _append_manifest(self, entry: dict[str, Any]) -> None:
        with self.manifest_path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(entry, ensure_ascii=False, default=str) + "\n")

    def _update_iocs(self, capture: RequestCapture, analysis: Analysis) -> None:
        context = f"{analysis.severity}:{','.join(analysis.cves) or 'generic'}:{capture.request_id}"
        lines: list[str] = []
        for kind, values in analysis.iocs.items():
            for value in values:
                cleaned = clean_text(value, 512).replace("\t", " ")
                if not cleaned:
                    continue
                key = (kind, cleaned)
                if key in self._ioc_keys:
                    continue
                while len(self._ioc_keys) >= _IOC_CAPACITY:
                    self._ioc_keys.popitem(last=False)
                self._ioc_keys[key] = None
                lines.append(
                    f"{kind}\t{cleaned}\t{capture.timestamp}\t{capture.timestamp}\t{context}\n"
                )
        if lines:
            with self.ioc_path.open("a", encoding="utf-8") as handle:
                handle.writelines(lines)


def rotate_file(path: Path, max_archives: int) -> bool:
    """Size-guard rotation: archive the file with a timestamp suffix once."""
    if not path.exists() or path.stat().st_size == 0:
        return False
    stamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
    archived = path.with_name(f"{path.name}.{stamp}")
    path.rename(archived)
    siblings = sorted(
        p for p in path.parent.glob(f"{path.name}.20*")
    )
    excess = siblings[:-max_archives] if max_archives > 0 else siblings
    for stale in excess:
        stale.unlink(missing_ok=True)
    return True


def retention_sweep(cfg: RetentionConfig, capture_dir: Path, log_dir: Path) -> dict[str, int]:
    """Enforce max files / max age on captures and rotate oversized logs."""
    stats: dict[str, int] = {}
    now = time.time()
    cutoff = now - cfg.max_age_days * 86400
    removed = 0
    candidates = [p for p in capture_dir.glob("*") if p.is_file() and p.name != "manifest.jsonl"]
    for path in candidates:
        try:
            if path.stat().st_mtime < cutoff:
                path.unlink()
                removed += 1
        except OSError:
            continue
    remaining = [p for p in candidates if p.exists()]
    if cfg.max_capture_files and len(remaining) > cfg.max_capture_files:
        remaining.sort(key=lambda p: p.stat().st_mtime)
        for path in remaining[: len(remaining) - cfg.max_capture_files]:
            try:
                path.unlink()
                removed += 1
            except OSError:
                continue
    stats["captures_removed"] = removed

    rotated = 0
    for log_file in (log_dir / "exploits.json", log_dir / "iocs.txt"):
        try:
            if log_file.exists() and log_file.stat().st_size > cfg.max_log_bytes:
                if rotate_file(log_file, cfg.max_log_archives):
                    rotated += 1
                    log_file.touch(exist_ok=True)
        except OSError:
            continue
    stats["logs_rotated"] = rotated
    return stats
