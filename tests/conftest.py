"""Shared builders: config with tmp storage, captures, multipart bodies."""
from __future__ import annotations

import os
import time
import uuid
from pathlib import Path

from phptopwn.capture import BodySpool, RequestCapture
from phptopwn.config import Config, load_config
from phptopwn.storage import utc_now

BOUNDARY = "----phptopwntest"
_UNSET: object = object()


def make_cfg(tmp: Path | None = None, **overrides: object) -> Config:
    env = {
        "PHPTOPWN_LARGE_MULTIPART_BYTES": "2048",
        "PHPTOPWN_MANY_PARTS": "4",
        "PHPTOPWN_PART_HEADER_BYTES": "256",
        "PHPTOPWN_HEADER_COUNT": "8",
        "PHPTOPWN_HEADER_BYTES": "1024",
        "PHPTOPWN_SLOW_GAP_SECONDS": "0.05",
        "PHPTOPWN_SLOW_TOTAL_SECONDS": "0.2",
    }
    if tmp is not None:
        env["PHPTOPWN_LOG_DIR"] = str(tmp / "logs")
        env["PHPTOPWN_CAPTURE_DIR"] = str(tmp / "payloads")
    if overrides:
        env.update(
            {
                f"PHPTOPWN_{key.upper().removeprefix('PHPTOPWN_')}": str(value)
                for key, value in overrides.items()
            }
        )
    return load_config(environ=env)


def multipart_body(parts: list[dict]) -> tuple[bytes, str]:
    chunks: list[bytes] = []
    for part in parts:
        chunks.append(f"--{BOUNDARY}\r\n".encode())
        disposition = f'Content-Disposition: form-data; name="{part["name"]}"'
        if part.get("filename"):
            disposition += f'; filename="{part["filename"]}"'
        chunks.append(disposition.encode("latin-1") + b"\r\n")
        for header in part.get("extra_headers", ()):
            chunks.append(f"{header}\r\n".encode("latin-1"))
        if part.get("content_type"):
            chunks.append(f"Content-Type: {part['content_type']}\r\n".encode())
        chunks.append(b"\r\n")
        data = part.get("data", "")
        chunks.append(data.encode("latin-1") if isinstance(data, str) else data)
        chunks.append(b"\r\n")
    chunks.append(f"--{BOUNDARY}--\r\n".encode())
    return b"".join(chunks), BOUNDARY


def build_capture(
    body: bytes = b"",
    method: str = "POST",
    path: str = "/upload.php",
    query: str = "",
    headers: dict[str, str] | None = None,
    declared: int | None = _UNSET,  # type: ignore[assignment]
    transfer_encoding: str = "",
    tls: bool = False,
    client_ip: str = "203.0.113.77",
    chunk_gaps: list[float] | None = None,
    body_seconds: float = 0.0,
    incomplete: bool = False,
    disconnected: bool = False,
    timed_out: bool = False,
    truncated_body: bool = False,
) -> RequestCapture:
    headers = dict(headers or {})
    header_map = {name.lower(): value for name, value in headers.items()}
    if declared is _UNSET:
        declared = len(body) if body else None
    headers_raw = [
        (name.lower(), value)
        for name, value in headers.items()
    ]
    capture = RequestCapture(
        request_id=uuid.uuid4().hex,
        timestamp=utc_now(),
        tls=tls,
        method=method,
        scheme="https" if tls else "http",
        host=header_map.get("host", "portal.example"),
        path=path,
        raw_path=path,
        query=query,
        http_version="1.1",
        client_ip=client_ip,
        client_port=55555,
        headers=headers_raw,
        header_map=header_map,
        header_count=len(headers_raw),
        header_bytes=sum(len(name) + len(value) + 4 for name, value in headers_raw),
        duplicate_headers=0,
        declared_content_length=declared,
        transfer_encoding=transfer_encoding,
        body=BodySpool(32 * 1024 * 1024),
    )
    capture.chunk_count = 1 if body else 0
    capture.chunk_gaps = list(chunk_gaps or [])
    capture.body_seconds = body_seconds
    capture.incomplete = incomplete
    capture.disconnected = disconnected
    capture.timed_out = timed_out
    capture.body.write(body, 2 * 1024 * 1024)
    if truncated_body:
        capture.body.truncated = True
    return capture


def wait_for(predicate, timeout: float = 2.0):
    deadline = time.time() + timeout
    while time.time() < deadline:
        result = predicate()
        if result:
            return result
        time.sleep(0.02)
    return None


def _isolate_env(tmp: Path) -> dict[str, str]:
    env = {key: value for key, value in os.environ.items() if not key.startswith("PHPTOPWN_")}
    env.update(
        {
            "PHPTOPWN_LOG_DIR": str(tmp / "logs"),
            "PHPTOPWN_CAPTURE_DIR": str(tmp / "payloads"),
        }
    )
    return env
