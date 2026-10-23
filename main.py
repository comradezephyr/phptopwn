#!/usr/bin/env python3
"""PHP2Shell honeypot for CVE-2026-109618 and CVE-2026-109619.

A *safe* high-interaction HTTP honeypot.  It emulates the parts of an Apache +
PHP-FPM file portal that attackers probe during PHP2Shell exploitation, records
the telemetry, and never executes, includes, evaluates or writes attacker code
into an executable location.

Design rules enforced in this file:
  * request bodies are streamed to a bounded spool; they are never parsed by PHP
  * payloads are only ever stored under ``captured_payloads/`` as inert bytes
  * no subprocess, eval, exec, shell, include or dynamic import of telemetry
  * responses are static templates rendered by this process
"""

from __future__ import annotations

import asyncio
import hashlib
import html
import json
import logging
import os
import re
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import parse_qsl, unquote, urlsplit

import uvicorn
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse, Response
from starlette.datastructures import MutableHeaders
from starlette.exceptions import HTTPException as StarletteHTTPException
from starlette.types import ASGIApp, Message, Receive, Scope, Send

APP_DIR = Path(__file__).resolve().parent
DEFAULT_BODY_CAP = 32 * 1024 * 1024

LOG = logging.getLogger("php2shell-honeypot")


def _env_str(name: str, default: str) -> str:
    value = os.environ.get(name)
    return value if value not in (None, "") else default


def _env_int(name: str, default: int, minimum: int = 0) -> int:
    raw = os.environ.get(name)
    if raw in (None, ""):
        return default
    try:
        return max(minimum, int(raw))
    except ValueError:
        return default


def _env_float(name: str, default: float, minimum: float = 0.0) -> float:
    raw = os.environ.get(name)
    if raw in (None, ""):
        return default
    try:
        return max(minimum, float(raw))
    except ValueError:
        return default


def _env_bool(name: str, default: bool) -> bool:
    raw = os.environ.get(name)
    if raw in (None, ""):
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on"}


def _env_path(name: str, default: str) -> Path:
    path = Path(_env_str(name, default)).expanduser()
    if not path.is_absolute():
        path = APP_DIR / path
    return path.resolve()


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


@dataclass(frozen=True)
class Settings:
    """Runtime configuration, entirely environment driven."""

    host: str = field(default_factory=lambda: _env_str("HONEYPOT_HOST", "0.0.0.0"))
    http_port: int = field(
        default_factory=lambda: _env_int("HONEYPOT_HTTP_PORT", _env_int("PORT", 8080), 1)
    )
    https_port: int = field(
        default_factory=lambda: _env_int("HONEYPOT_HTTPS_PORT", 8443, 1)
    )
    enable_tls: bool = field(default_factory=lambda: _env_bool("HONEYPOT_TLS", False))
    cert_file: Path = field(
        default_factory=lambda: _env_path("HONEYPOT_CERT_FILE", "./certs/honeypot.crt")
    )
    key_file: Path = field(
        default_factory=lambda: _env_path("HONEYPOT_KEY_FILE", "./certs/honeypot.key")
    )
    log_dir: Path = field(default_factory=lambda: _env_path("HONEYPOT_LOG_DIR", "./logs"))
    payload_dir: Path = field(
        default_factory=lambda: _env_path("HONEYPOT_PAYLOAD_DIR", "./captured_payloads")
    )
    tmp_dir: Path = field(
        default_factory=lambda: _env_path("HONEYPOT_TMP_DIR", "./logs/tmp")
    )

    # Safety limits (never allocate more than this per request).
    max_body_bytes: int = field(
        default_factory=lambda: _env_int("HONEYPOT_MAX_BODY_BYTES", DEFAULT_BODY_CAP, 1024)
    )
    probe_bytes: int = field(
        default_factory=lambda: _env_int("HONEYPOT_PROBE_BYTES", 2 * 1024 * 1024, 4096)
    )
    max_artifact_bytes: int = field(
        default_factory=lambda: _env_int("HONEYPOT_MAX_ARTIFACT_BYTES", 4 * 1024 * 1024, 4096)
    )
    max_artifact_parts: int = field(
        default_factory=lambda: _env_int("HONEYPOT_MAX_ARTIFACT_PARTS", 8, 1)
    )
    body_timeout_seconds: float = field(
        default_factory=lambda: _env_float("HONEYPOT_BODY_TIMEOUT_SECONDS", 30.0, 0.5)
    )

    # CVE-2026-109618 heuristics.
    large_multipart_bytes: int = field(
        default_factory=lambda: _env_int("HONEYPOT_LARGE_MULTIPART_BYTES", 1024 * 1024, 256)
    )
    many_parts_threshold: int = field(
        default_factory=lambda: _env_int("HONEYPOT_MANY_PARTS", 32, 2)
    )
    part_header_bytes: int = field(
        default_factory=lambda: _env_int("HONEYPOT_PART_HEADER_BYTES", 4096, 128)
    )
    header_count_threshold: int = field(
        default_factory=lambda: _env_int("HONEYPOT_HEADER_COUNT", 60, 5)
    )
    header_bytes_threshold: int = field(
        default_factory=lambda: _env_int("HONEYPOT_HEADER_BYTES", 16384, 512)
    )

    # CVE-2026-109619 heuristics (slow TCP stream / session upload progress).
    slow_chunk_gap_seconds: float = field(
        default_factory=lambda: _env_float("HONEYPOT_SLOW_GAP_SECONDS", 2.0, 0.01)
    )
    slow_total_seconds: float = field(
        default_factory=lambda: _env_float("HONEYPOT_SLOW_TOTAL_SECONDS", 5.0, 0.01)
    )

    log_all_requests: bool = field(
        default_factory=lambda: _env_bool("HONEYPOT_LOG_ALL", True)
    )
    trust_proxy_headers: bool = field(
        default_factory=lambda: _env_bool("HONEYPOT_TRUST_PROXY_HEADERS", False)
    )

    # Deception fingerprints.
    server_token: str = field(
        default_factory=lambda: _env_str("HONEYPOT_SERVER_TOKEN", "Apache/2.4.52 (Ubuntu)")
    )
    powered_by: str = field(
        default_factory=lambda: _env_str("HONEYPOT_POWERED_BY", "PHP/8.1.2")
    )
    php_version: str = field(
        default_factory=lambda: _env_str("HONEYPOT_PHP_VERSION", "8.1.2")
    )
    memory_limit: str = field(
        default_factory=lambda: _env_str("HONEYPOT_MEMORY_LIMIT", "128M")
    )
    server_name: str = field(
        default_factory=lambda: _env_str("HONEYPOT_SERVER_NAME", "intranet.acme.local")
    )


SETTINGS = Settings()


# --------------------------------------------------------------------------- #
# Data models
# --------------------------------------------------------------------------- #
@dataclass
class BodySpool:
    """Bounded, on-disk spool with an in-memory probe prefix and streaming hash."""

    max_bytes: int
    spool_dir: Path
    hash: Any = field(init=False)
    size: int = 0
    stored_bytes: int = 0
    truncated: bool = False
    probe: bytearray = field(default_factory=bytearray)
    _spool: Any = field(init=False)
    _replay_started: bool = False
    _replay_finished: bool = False

    def __post_init__(self) -> None:
        import tempfile

        self.hash = hashlib.sha256()
        self._spool = tempfile.SpooledTemporaryFile(
            max_size=1024 * 1024,
            dir=str(self.spool_dir),
            prefix="body-",
            suffix=".spool",
        )

    def write(self, chunk: bytes, probe_limit: int) -> None:
        self.hash.update(chunk)
        self.size += len(chunk)
        remaining = self.max_bytes - self.stored_bytes
        if remaining > 0:
            keep = chunk[:remaining]
            self._spool.write(keep)
            self.stored_bytes += len(keep)
        if len(chunk) > max(remaining, 0):
            self.truncated = True
        if len(self.probe) < probe_limit:
            self.probe.extend(chunk[: probe_limit - len(self.probe)])

    def digest(self) -> str:
        return self.hash.hexdigest()

    def read_replay_chunk(self, size: int = 65536) -> bytes:
        if not self._replay_started:
            self._replay_started = True
            self._spool.seek(0)
        if self._replay_finished:
            return b""
        chunk = self._spool.read(size)
        if not chunk:
            self._replay_finished = True
        return chunk

    def save_to(self, path: Path, limit: int | None = None) -> int:
        self._spool.seek(0)
        remaining = self.stored_bytes if limit is None else max(0, min(limit, self.stored_bytes))
        written = 0
        with path.open("wb") as handle:
            while remaining > 0:
                chunk = self._spool.read(min(1024 * 1024, remaining))
                if not chunk:
                    break
                handle.write(chunk)
                written += len(chunk)
                remaining -= len(chunk)
        return written

    def close(self) -> None:
        try:
            self._spool.close()
        except Exception:  # pragma: no cover - defensive close
            pass


@dataclass
class MultipartPart:
    index: int
    name: str | None
    filename: str | None
    content_type: str | None
    headers: dict[str, str]
    header_size: int
    size: int
    sha256: str
    data: bytes
    truncated: bool = False


@dataclass
class MultipartResult:
    boundary: str
    boundary_found: bool = False
    closed: bool = False
    malformed: bool = False
    nested_boundary: bool = False
    truncated: bool = False
    part_limit_reached: bool = False
    boundary_occurrences: int = 0
    parts: list[MultipartPart] = field(default_factory=list)
    total_header_bytes: int = 0
    max_header_size: int = 0
    folded_headers: bool = False
    duplicate_filenames: list[str] = field(default_factory=list)
    long_filenames: list[str] = field(default_factory=list)
    filename_traversal: list[str] = field(default_factory=list)

    @property
    def file_parts(self) -> list[MultipartPart]:
        return [part for part in self.parts if part.filename is not None]

    def to_dict(self) -> dict[str, Any]:
        return {
            "boundary": self.boundary,
            "boundary_found": self.boundary_found,
            "closed": self.closed,
            "malformed": self.malformed,
            "nested_boundary": self.nested_boundary,
            "truncated": self.truncated,
            "part_limit_reached": self.part_limit_reached,
            "boundary_occurrences": self.boundary_occurrences,
            "part_count": len(self.parts),
            "file_part_count": len(self.file_parts),
            "total_header_bytes": self.total_header_bytes,
            "max_header_size": self.max_header_size,
            "folded_headers": self.folded_headers,
            "duplicate_filenames": self.duplicate_filenames,
            "long_filenames": self.long_filenames,
            "filename_traversal": self.filename_traversal,
            "parts": [
                {
                    "index": part.index,
                    "name": part.name,
                    "filename": part.filename,
                    "content_type": part.content_type,
                    "header_size": part.header_size,
                    "size": part.size,
                    "sha256": part.sha256,
                    "truncated": part.truncated,
                }
                for part in self.parts
            ],
        }


SEVERITY_RANK = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


@dataclass
class Signal:
    id: str
    severity: str
    description: str
    cve: str | None = None
    evidence: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "id": self.id,
            "severity": self.severity,
            "description": self.description,
        }
        if self.cve:
            payload["cve"] = self.cve
        if self.evidence:
            payload["evidence"] = self.evidence
        return payload


@dataclass
class Analysis:
    is_exploit: bool = False
    severity: str = "info"
    cves: list[str] = field(default_factory=list)
    signals: list[Signal] = field(default_factory=list)
    command_droppers: list[dict[str, Any]] = field(default_factory=list)
    webshell_markers: list[str] = field(default_factory=list)
    iocs: dict[str, list[str]] = field(default_factory=dict)

    def add(self, signal: Signal) -> None:
        self.signals.append(signal)
        if signal.cve and signal.cve not in self.cves:
            self.cves.append(signal.cve)
        if SEVERITY_RANK.get(signal.severity, 0) > SEVERITY_RANK.get(self.severity, 0):
            self.severity = signal.severity
        if SEVERITY_RANK.get(signal.severity, 0) >= SEVERITY_RANK["medium"]:
            self.is_exploit = True

    def add_ioc(self, kind: str, value: str) -> None:
        bucket = self.iocs.setdefault(kind, [])
        if value and value not in bucket:
            bucket.append(value)

    def to_dict(self) -> dict[str, Any]:
        return {
            "is_exploit": self.is_exploit,
            "severity": self.severity,
            "cves": self.cves,
            "signals": [signal.to_dict() for signal in self.signals],
            "command_droppers": self.command_droppers,
            "webshell_markers": self.webshell_markers,
            "iocs": self.iocs,
        }


@dataclass
class RequestCapture:
    request_id: str
    timestamp: str
    tls: bool
    method: str
    scheme: str
    host: str
    path: str
    raw_path: str
    query: str
    http_version: str
    client_ip: str
    client_port: int | None
    headers: list[tuple[str, str]]
    header_map: dict[str, str]
    header_count: int
    header_bytes: int
    duplicate_headers: int
    declared_content_length: int | None
    transfer_encoding: str
    body: BodySpool
    chunk_count: int = 0
    chunk_gaps: list[float] = field(default_factory=list)
    first_byte_seconds: float = 0.0
    body_seconds: float = 0.0
    incomplete: bool = False
    disconnected: bool = False
    timed_out: bool = False
    response_started: bool = False
    status_code: int | None = None
    response_headers: dict[str, str] = field(default_factory=dict)
    multipart: MultipartResult | None = None
    form: dict[str, str] = field(default_factory=dict)
    query_params: dict[str, str] = field(default_factory=dict)
    analysis: Analysis | None = None
    error: str | None = None

    @property
    def body_size(self) -> int:
        return self.body.size

    @property
    def body_sha256(self) -> str:
        return self.body.digest()

    @property
    def body_probe(self) -> bytes:
        return bytes(self.body.probe)

    @property
    def content_type(self) -> str:
        return self.header_map.get("content-type", "")

    @property
    def content_length(self) -> int | None:
        return self.declared_content_length

    @property
    def max_chunk_gap(self) -> float:
        return max(self.chunk_gaps, default=0.0)


# --------------------------------------------------------------------------- #
# Safe multipart / form parsing (pure Python, no PHP, no temp executables)
# --------------------------------------------------------------------------- #
_CONTENT_TYPE_PARAM = re.compile(
    r"""([\w*.\-]+)\s*=\s*(?:"([^"]*)"|'([^']*)'|([^;\s]+))""", re.IGNORECASE
)
_TRAVERSAL = re.compile(r"(?:^[\\/]|\.\.[\\/]|%2e%2e[\\/])", re.IGNORECASE)


def parse_content_type(value: str) -> tuple[str, dict[str, str]]:
    if not value:
        return "", {}
    mime = value.split(";", 1)[0].strip().lower()
    params: dict[str, str] = {}
    for match in _CONTENT_TYPE_PARAM.finditer(value):
        key = match.group(1).lower()
        raw = next((group for group in match.groups()[1:] if group is not None), "")
        params[key] = raw
    return mime, params


def _extract_disposition(value: str, key: str) -> str | None:
    pattern = re.compile(
        rf"""\b{key}\s*=\s*(?:"((?:[^"\\]|\\.)*)"|'([^']*)'|([^;\s]+))""",
        re.IGNORECASE,
    )
    match = pattern.search(value)
    if not match:
        return None
    raw = next((group for group in match.groups() if group is not None), "")
    return raw.replace('\\"', '"').replace("\\\\", "\\")


def extract_filename(disposition: str) -> str | None:
    star = re.search(r"filename\*\s*=\s*([^;]+)", disposition, re.IGNORECASE)
    if star:
        raw = star.group(1).strip().strip('"')
        if "''" in raw:
            charset, _, encoded = raw.partition("''")
            try:
                return unquote(encoded, encoding=charset or "utf-8", errors="replace")
            except (LookupError, UnicodeDecodeError):
                return unquote(encoded)
        return unquote(raw)
    filename = _extract_disposition(disposition, "filename")
    return filename


def parse_part_headers(blob: bytes) -> tuple[dict[str, str], int, bool]:
    text = blob.decode("latin-1", "replace")
    headers: dict[str, str] = {}
    folded = False
    last_key: str | None = None
    for line in re.split(r"\r?\n", text):
        if not line:
            continue
        if line[0] in " \t" and last_key is not None:
            folded = True
            headers[last_key] = f"{headers[last_key]} {line.strip()}"
            continue
        if ":" not in line:
            folded = True
            continue
        key, _, val = line.partition(":")
        last_key = key.strip().lower()
        headers[last_key] = val.strip()
    return headers, len(blob), folded


def parse_multipart(
    data: bytes,
    boundary: str,
    truncated: bool = False,
    max_parts: int = 512,
) -> MultipartResult:
    result = MultipartResult(boundary=boundary, truncated=truncated)
    if not boundary:
        result.malformed = True
        return result

    delimiter = b"--" + boundary.encode("latin-1", "replace")
    if delimiter not in data:
        return result

    result.boundary_found = True
    segments = data.split(delimiter)
    result.boundary_occurrences = len(segments) - 1
    seen_filenames: list[str] = []

    for raw in segments[1:]:
        if len(result.parts) >= max_parts:
            # Hostile boundary floods must not turn into unbounded parser work.
            result.part_limit_reached = True
            break
        if raw.startswith(b"--"):
            result.closed = True
            break
        if raw.startswith(b"\r\n"):
            raw = raw[2:]
        elif raw.startswith(b"\n"):
            raw = raw[1:]
        elif raw[:1] in (b" ", b"\t"):
            raw = raw.lstrip()
        else:
            # Data directly after a boundary without CRLF: mangled framing.
            result.malformed = True

        separator = raw.find(b"\r\n\r\n")
        sep_len = 4
        if separator < 0:
            separator = raw.find(b"\n\n")
            sep_len = 2
        if separator < 0:
            result.malformed = True
            continue

        header_blob = raw[:separator]
        content = raw[separator + sep_len :]
        if content.endswith(b"\r\n"):
            content = content[:-2]
        elif content.endswith(b"\n"):
            content = content[:-1]

        headers, header_size, folded = parse_part_headers(header_blob)
        disposition = headers.get("content-disposition", "")
        name = _extract_disposition(disposition, "name")
        filename = extract_filename(disposition)
        content_type = headers.get("content-type")

        if content_type and "boundary=" in content_type.lower():
            nested_mime, nested_params = parse_content_type(content_type)
            nested_boundary = nested_params.get("boundary", "")
            if nested_mime.startswith("multipart/") and nested_boundary:
                if content.startswith(b"--" + nested_boundary.encode("latin-1", "replace")):
                    result.nested_boundary = True

        if filename and filename not in seen_filenames:
            seen_filenames.append(filename)
        elif filename and filename not in result.duplicate_filenames:
            result.duplicate_filenames.append(filename)

        if filename:
            if len(filename) > 255:
                result.long_filenames.append(filename[:300])
            if "\x00" in filename or _TRAVERSAL.search(filename):
                result.filename_traversal.append(filename[:300])

        part = MultipartPart(
            index=len(result.parts),
            name=name,
            filename=filename or None,
            content_type=content_type,
            headers=headers,
            header_size=header_size,
            size=len(content),
            sha256=hashlib.sha256(content).hexdigest(),
            data=content,
            truncated=False,
        )
        result.parts.append(part)
        result.total_header_bytes += header_size
        result.max_header_size = max(result.max_header_size, header_size)
        result.folded_headers = result.folded_headers or folded

    if truncated and not result.closed and result.parts:
        # The probe prefix cut the final part mid-stream; earlier parts are whole.
        result.parts[-1].truncated = True

    return result


def parse_urlencoded(data: bytes, max_fields: int = 128) -> dict[str, str]:
    try:
        text = data[: 256 * 1024].decode("utf-8", "replace")
    except Exception:
        return {}
    try:
        pairs = parse_qsl(text, keep_blank_values=True, max_num_fields=max_fields)
    except ValueError:
        pairs = parse_qsl(text[: 32 * 1024], keep_blank_values=True)
    return {key: value[:8192] for key, value in pairs}


def parse_query(query: str, max_fields: int = 128) -> dict[str, str]:
    if not query:
        return {}
    try:
        pairs = parse_qsl(query, keep_blank_values=True, max_num_fields=max_fields)
    except ValueError:
        pairs = parse_qsl(query[: 8192], keep_blank_values=True)
    return {key: value[:8192] for key, value in pairs}


def enrich_request(capture: RequestCapture) -> None:
    """Populate query/form/multipart views from the bounded body probe."""
    mime, params = parse_content_type(capture.content_type)
    capture.query_params = parse_query(capture.query)
    probe = capture.body_probe

    if mime == "multipart/form-data":
        boundary = params.get("boundary", "")
        capture.multipart = parse_multipart(
            probe, boundary, truncated=len(probe) < capture.body_size
        )
        for part in capture.multipart.parts:
            if part.filename is None and part.name:
                capture.form[part.name] = part.data[:8192].decode("utf-8", "replace")
    elif mime == "application/x-www-form-urlencoded":
        capture.form = parse_urlencoded(probe)
        for key, value in capture.query_params.items():
            capture.form.setdefault(key, value)


# --------------------------------------------------------------------------- #
# Detection signatures
# --------------------------------------------------------------------------- #
DROPPER_PATTERNS: list[tuple[str, re.Pattern[bytes]]] = [
    ("curl", re.compile(rb"\bcurl(?:\.exe)?\b[^\r\n\x00]{0,300}", re.IGNORECASE)),
    ("wget", re.compile(rb"\bwget(?:\.exe)?\b[^\r\n\x00]{0,300}", re.IGNORECASE)),
    ("chmod", re.compile(rb"\bchmod\s+(?:[0-7]{3,4}|\+x)[^\r\n\x00]{0,200}", re.IGNORECASE)),
    ("shell", re.compile(rb"\b(?:ba|z|k)?sh\s+-c\s+[^\r\n\x00]{0,300}", re.IGNORECASE)),
    ("netcat", re.compile(rb"\b(?:nc|ncat|netcat)\b[^\r\n\x00]{0,200}", re.IGNORECASE)),
    ("base64", re.compile(rb"\bbase64\s+(?:-d|--decode|-D)[^\r\n\x00]{0,200}", re.IGNORECASE)),
    ("python", re.compile(rb"\bpython[0-9.]*\s+-c\s+[^\r\n\x00]{0,300}", re.IGNORECASE)),
    ("perl", re.compile(rb"\bperl\s+-e\s+[^\r\n\x00]{0,300}", re.IGNORECASE)),
    ("powershell", re.compile(rb"\bpowershell(?:\.exe)?\b[^\r\n\x00]{0,300}", re.IGNORECASE)),
    ("reverse_shell", re.compile(rb"(?:/dev/tcp/|mkfifo\s+|bash\s+-i\s+>&)", re.IGNORECASE)),
    ("php_webshell", re.compile(rb"<\?php[\s\S]{0,400}", re.IGNORECASE)),
    (
        "php_exec",
        re.compile(
            rb"\b(?:eval|assert|system|exec|shell_exec|passthru|popen|proc_open|create_function)\s*\(",
            re.IGNORECASE,
        ),
    ),
]

WEBSHELL_MARKERS: list[bytes] = [
    b"<?php",
    b"<?=",
    b"eval(",
    b"assert($_",
    b"system(",
    b"shell_exec",
    b"passthru",
    b"proc_open",
    b"popen(",
    b"base64_decode",
    b"gzinflate(",
    b"str_rot13(",
    b"create_function",
]

SCANNER_UA = re.compile(
    r"(sqlmap|nikto|nuclei|masscan|zgrab|nmap|dirbuster|gobuster|feroxbuster|"
    r"wpscan|joomscan|acunetix|nessus|openvas|metasploit|python-requests|"
    r"go-http-client|curl/|wget/|libwww-perl|httpclient)",
    re.IGNORECASE,
)

IPV4_RE = re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b")
URL_RE = re.compile(r"https?://[^\s'\"<>\\\x00]{4,300}", re.IGNORECASE)
COMMAND_PARAMS = {"cmd", "exec", "command", "shell", "run", "system", "eval", "code"}
SCANNER_EXTENSIONS = (".php", ".phtml", ".php5", ".php7", ".phar", ".pht")


def _decode(data: bytes) -> str:
    return data.decode("utf-8", "replace")


def _find_droppers(text: str) -> list[dict[str, str]]:
    found: list[dict[str, str]] = []
    seen: set[tuple[str, str]] = set()
    raw = text.encode("utf-8", "replace")[: 512 * 1024]
    for tool, pattern in DROPPER_PATTERNS:
        for match in pattern.finditer(raw):
            command = _decode(match.group(0)).strip()
            command = command.split("\r\n--")[0].strip()
            key = (tool, command)
            if not command or key in seen:
                continue
            seen.add(key)
            found.append({"tool": tool, "command": command[:600]})
            if len(found) >= 25:
                return found
    return found


def _webshell_markers(data: bytes) -> list[str]:
    lowered = data.lower()
    return [marker.decode("latin-1") for marker in WEBSHELL_MARKERS if marker in lowered]


def _add_signal(
    analysis: Analysis,
    signal_id: str,
    severity: str,
    description: str,
    cve: str | None = None,
    **evidence: Any,
) -> None:
    analysis.add(
        Signal(
            id=signal_id,
            severity=severity,
            description=description,
            cve=cve,
            evidence={key: value for key, value in evidence.items() if value is not None},
        )
    )


def analyze(capture: RequestCapture, settings: Settings) -> Analysis:
    """Classify a request against both PHP2Shell CVE signatures.

    Only bounded request metadata and the in-memory probe prefix are inspected;
    nothing is ever handed to an interpreter.
    """
    analysis = Analysis()
    mime, _ = parse_content_type(capture.content_type)
    is_multipart = mime == "multipart/form-data"
    method = capture.method.upper()
    probe = capture.body_probe
    probe_lower = probe[: 512 * 1024].lower()
    mp = capture.multipart

    if capture.client_ip:
        analysis.add_ioc("ip", capture.client_ip)

    # ------------------------------------------------------------------ #
    # CVE-2026-109618: memory-exhaustion multipart / mangled framing
    # ------------------------------------------------------------------ #
    if is_multipart and method in {"POST", "PUT", "PATCH"}:
        if capture.body_size >= settings.large_multipart_bytes:
            _add_signal(
                analysis,
                "large_multipart_upload",
                "high",
                "Multipart upload exceeds the PHP2Shell OOM trigger threshold",
                "CVE-2026-109618",
                body_bytes=capture.body_size,
                threshold_bytes=settings.large_multipart_bytes,
                declared_content_length=capture.declared_content_length,
            )

    if mp is not None:
        if not mp.boundary:
            _add_signal(
                analysis,
                "multipart_missing_boundary",
                "high",
                "multipart/form-data request without a boundary parameter",
                "CVE-2026-109618",
            )
        elif not mp.boundary_found:
            _add_signal(
                analysis,
                "mangled_multipart_boundary",
                "high",
                "Declared multipart boundary never appears in the body",
                "CVE-2026-109618",
                boundary=mp.boundary[:200],
                body_bytes=capture.body_size,
            )

        if len(mp.parts) >= settings.many_parts_threshold:
            _add_signal(
                analysis,
                "excessive_multipart_parts",
                "high",
                "Multipart body contains an abusive number of parts",
                "CVE-2026-109618",
                part_count=len(mp.parts),
                threshold=settings.many_parts_threshold,
            )
        if mp.max_header_size >= settings.part_header_bytes:
            _add_signal(
                analysis,
                "oversized_part_headers",
                "high",
                "Multipart part headers exceed normal PHP parser limits",
                "CVE-2026-109618",
                max_header_bytes=mp.max_header_size,
                threshold=settings.part_header_bytes,
            )
        if mp.folded_headers:
            _add_signal(
                analysis,
                "folded_multipart_headers",
                "medium",
                "Folded or malformed multipart part headers detected",
                "CVE-2026-109618",
            )
        if len(mp.file_parts) >= 8:
            _add_signal(
                analysis,
                "mass_file_upload_fields",
                "high",
                "Multipart body declares an excessive number of file fields",
                "CVE-2026-109618",
                file_part_count=len(mp.file_parts),
            )
        if mp.duplicate_filenames:
            _add_signal(
                analysis,
                "duplicate_upload_filenames",
                "medium",
                "Duplicate uploaded filenames detected",
                "CVE-2026-109618",
                filenames=mp.duplicate_filenames[:10],
            )
        if mp.long_filenames:
            _add_signal(
                analysis,
                "oversized_upload_filename",
                "medium",
                "Uploaded filename exceeds filesystem limits",
                "CVE-2026-109618",
                filenames=mp.long_filenames[:5],
            )
        if mp.nested_boundary:
            _add_signal(
                analysis,
                "nested_multipart_boundary",
                "high",
                "Nested multipart boundary can desynchronise the PHP parser",
                "CVE-2026-109618",
            )
        if mp.part_limit_reached:
            _add_signal(
                analysis,
                "multipart_part_limit_exceeded",
                "high",
                "Multipart part count hit the safe parser limit (boundary flood)",
                "CVE-2026-109618",
                parsed_parts=len(mp.parts),
            )
        if mp.malformed and not mp.truncated:
            _add_signal(
                analysis,
                "mangled_multipart_body",
                "high",
                "Malformed multipart framing (missing CRLF or part separators)",
                "CVE-2026-109618",
            )
        if mp.filename_traversal:
            _add_signal(
                analysis,
                "filename_path_traversal",
                "medium",
                "Uploaded filename attempts directory traversal",
                filenames=mp.filename_traversal[:10],
            )

    declared = capture.declared_content_length
    if declared is not None:
        if declared > settings.max_body_bytes:
            _add_signal(
                analysis,
                "content_length_overflow",
                "high",
                "Declared Content-Length far exceeds safe PHP request limits",
                "CVE-2026-109618",
                declared_content_length=declared,
                capture_cap=settings.max_body_bytes,
            )
        if capture.body_size < declared and not capture.body.truncated:
            _add_signal(
                analysis,
                "truncated_request_body",
                "high",
                "Client declared more bytes than it delivered (parser desync / OOM bait)",
                "CVE-2026-109618",
                declared_content_length=declared,
                received_bytes=capture.body_size,
            )

    if (
        capture.header_count >= settings.header_count_threshold
        or capture.header_bytes >= settings.header_bytes_threshold
    ):
        _add_signal(
            analysis,
            "header_flooding",
            "medium",
            "Oversized HTTP header block",
            "CVE-2026-109618",
            header_count=capture.header_count,
            header_bytes=capture.header_bytes,
        )

    if capture.transfer_encoding and declared is not None:
        _add_signal(
            analysis,
            "conflicting_length_headers",
            "high",
            "Request contains both Transfer-Encoding and Content-Length",
            "CVE-2026-109618",
            transfer_encoding=capture.transfer_encoding[:80],
            declared_content_length=declared,
        )

    # ------------------------------------------------------------------ #
    # CVE-2026-109619: PHP_SESSION_UPLOAD_PROGRESS and paused TCP streams
    # ------------------------------------------------------------------ #
    session_markers = [
        marker
        for marker in (
            b"php_session_upload_progress",
            b"session.upload_progress.name",
            b"session.upload_progress.cleanup",
            b"session.upload_progress.enabled",
        )
        if marker in probe_lower
    ]
    session_header_hits = [
        key
        for key in capture.header_map
        if key in {"php_value", "php_admin_value", "php_session_upload_progress", "php_ini"}
    ]

    if session_markers:
        _add_signal(
            analysis,
            "php_session_upload_progress",
            "high",
            "PHP_SESSION_UPLOAD_PROGRESS marker present in request body",
            "CVE-2026-109619",
            markers=[marker.decode() for marker in session_markers],
            form_fields=[
                key for key in capture.form if key.upper() == "PHP_SESSION_UPLOAD_PROGRESS"
            ],
        )
    if session_header_hits:
        _add_signal(
            analysis,
            "php_ini_override_header",
            "high",
            "PHP INI override / session progress marker supplied as HTTP header",
            "CVE-2026-109619",
            headers=session_header_hits,
        )

    ini_markers = [
        marker
        for marker in (
            b"allow_url_include",
            b"auto_prepend_file",
            b"auto_append_file",
            b"disable_functions",
        )
        if marker in probe_lower
    ]
    if ini_markers and not session_header_hits:
        _add_signal(
            analysis,
            "php_ini_override_payload",
            "high",
            "PHP INI manipulation tokens embedded in request",
            "CVE-2026-109619",
            markers=[marker.decode() for marker in ini_markers],
        )

    if capture.max_chunk_gap >= settings.slow_chunk_gap_seconds:
        _add_signal(
            analysis,
            "tcp_stream_pause",
            "high",
            "Attacker deliberately paused the TCP stream mid-upload",
            "CVE-2026-109619",
            max_chunk_gap_seconds=round(capture.max_chunk_gap, 3),
            threshold_seconds=settings.slow_chunk_gap_seconds,
            chunk_count=capture.chunk_count,
        )
    if capture.body_seconds >= settings.slow_total_seconds and capture.body_size > 0:
        _add_signal(
            analysis,
            "slow_body_delivery",
            "high",
            "Request body delivered slowly over an extended window",
            "CVE-2026-109619",
            body_seconds=round(capture.body_seconds, 3),
            threshold_seconds=settings.slow_total_seconds,
            body_bytes=capture.body_size,
        )
    if capture.incomplete or capture.disconnected:
        _add_signal(
            analysis,
            "incomplete_upload_stream",
            "high",
            "Upload stream ended before a complete body was received",
            "CVE-2026-109619",
            disconnected=capture.disconnected,
            received_bytes=capture.body_size,
            declared_content_length=declared,
        )
    if capture.timed_out:
        _add_signal(
            analysis,
            "body_read_timeout",
            "high",
            "Client stalled the request body beyond the read timeout (slow upload race)",
            "CVE-2026-109619",
            timeout_seconds=settings.body_timeout_seconds,
            received_bytes=capture.body_size,
        )
    if capture.body.truncated:
        _add_signal(
            analysis,
            "body_exceeds_capture_cap",
            "medium",
            "Request body exceeded the honeypot capture cap and was truncated",
            body_bytes=capture.body_size,
            stored_bytes=capture.body.stored_bytes,
            capture_cap=settings.max_body_bytes,
        )
    if "100-continue" in capture.header_map.get("expect", "").lower() and is_multipart:
        _add_signal(
            analysis,
            "expect_100_continue_upload",
            "low",
            "Expect: 100-continue used with a multipart upload",
            body_bytes=capture.body_size,
        )
    if capture.transfer_encoding.lower() == "chunked" and is_multipart:
        _add_signal(
            analysis,
            "chunked_multipart_upload",
            "low",
            "Chunked multipart upload (stream desync primitive)",
        )

    # ------------------------------------------------------------------ #
    # Generic web-shell / dropper tradecraft
    # ------------------------------------------------------------------ #
    text = _decode(probe)
    form_values = list(capture.form.values()) + list(capture.query_params.values())
    scan_text = text + "\n" + "\n".join(form_values)
    droppers = _find_droppers(scan_text)
    if droppers:
        analysis.command_droppers = droppers
        _add_signal(
            analysis,
            "command_dropper",
            "high",
            "Command downloader / execution string observed in payload",
            tools=sorted({dropper["tool"] for dropper in droppers}),
            commands=[dropper["command"][:300] for dropper in droppers[:5]],
        )

    markers = _webshell_markers(probe)
    analysis.webshell_markers = sorted(set(markers))
    file_parts = mp.file_parts if mp else []
    suspicious_parts = [
        part
        for part in file_parts
        if _webshell_markers(part.data)
        or (part.filename or "").lower().endswith(SCANNER_EXTENSIONS)
    ]
    if suspicious_parts:
        _add_signal(
            analysis,
            "webshell_upload",
            "high",
            "Uploaded file contains executable web-shell content",
            filenames=[(part.filename or "")[:200] for part in suspicious_parts[:10]],
            sha256=[part.sha256 for part in suspicious_parts[:10]],
        )
    elif markers and (capture.form or capture.query_params):
        _add_signal(
            analysis,
            "php_code_in_request",
            "medium",
            "PHP execution primitives found in request fields",
            markers=sorted(set(markers))[:10],
        )

    if session_markers and markers:
        _add_signal(
            analysis,
            "session_progress_webshell_race",
            "high",
            "PHP_SESSION_UPLOAD_PROGRESS combined with PHP code (session file poisoning race)",
            "CVE-2026-109619",
            markers=sorted(set(markers))[:10],
        )

    command_keys = sorted(
        {
            key
            for key, value in list(capture.query_params.items()) + list(capture.form.items())
            if key.lower() in COMMAND_PARAMS and str(value).strip()
        }
    )
    if command_keys:
        _add_signal(
            analysis,
            "command_parameter",
            "medium",
            "Command execution parameter supplied in request",
            parameters=command_keys,
        )

    if capture.path in {
        "/.env",
        "/.git/config",
        "/wp-config.php",
        "/config.php",
        "/phpinfo.php",
        "/server-status",
        "/shell.php",
    }:
        _add_signal(
            analysis,
            "sensitive_path_probe",
            "low",
            "Reconnaissance request for a sensitive deployment path",
            path=capture.path,
        )

    user_agent = capture.header_map.get("user-agent", "")
    if user_agent and SCANNER_UA.search(user_agent):
        _add_signal(
            analysis,
            "scanner_user_agent",
            "low",
            "User-Agent matches known reconnaissance tooling",
            user_agent=user_agent[:300],
        )

    # ------------------------------------------------------------------ #
    # IOC harvesting (bounded, deduplicated)
    # ------------------------------------------------------------------ #
    ioc_text = text[: 256 * 1024] + "\n" + "\n".join(value[:4096] for value in form_values[:64])
    for ip in sorted(set(IPV4_RE.findall(ioc_text)))[:50]:
        analysis.add_ioc("ip", ip)
    for url in sorted(set(URL_RE.findall(ioc_text)))[:50]:
        analysis.add_ioc("url", url[:400])
        try:
            host = urlsplit(url).hostname
        except ValueError:
            host = None
        if host:
            analysis.add_ioc("domain", host[:255])
    for part in file_parts[:50]:
        if part.filename:
            analysis.add_ioc("filename", part.filename[:300])

    if analysis.is_exploit:
        analysis.add_ioc("sha256", capture.body_sha256)
        for part in suspicious_parts[:25]:
            analysis.add_ioc("sha256", part.sha256)

    return analysis


# --------------------------------------------------------------------------- #
# Artifact persistence
# --------------------------------------------------------------------------- #
SENSOR_VERSION = "1.0.0"

IOC_HEADER = (
    "# PHP2Shell honeypot IOC feed (tab separated)\n"
    "# type\tvalue\tfirst_seen\tlast_seen\tcontext\n"
    "# IP blocklist: awk -F'\\t' '!/^#/ && $1==\"ip\" {print $2}' logs/iocs.txt\n"
)

_MIME_EXT = {
    "application/x-php": ".php",
    "application/x-httpd-php": ".php",
    "application/x-sh": ".sh",
    "application/javascript": ".js",
    "text/x-python": ".py",
    "application/x-python": ".py",
    "text/plain": ".txt",
}


def _part_extension(part: MultipartPart) -> str:
    filename = (part.filename or "").lower()
    for suffix in (".php", ".phtml", ".php5", ".php7", ".phar", ".pht"):
        if filename.endswith(suffix):
            return ".php"
    for suffix in (".sh", ".bash", ".py", ".pl", ".js", ".txt", ".html", ".htm"):
        if filename.endswith(suffix):
            return suffix
    if part.content_type:
        extension = _MIME_EXT.get(part.content_type.split(";", 1)[0].strip().lower())
        if extension:
            return extension
    return ".bin"


def _body_extension(capture: RequestCapture) -> str:
    mime, _ = parse_content_type(capture.content_type)
    if mime == "multipart/form-data":
        return ".multipart"
    if mime == "application/x-www-form-urlencoded":
        return ".form"
    if mime in _MIME_EXT:
        return _MIME_EXT[mime]
    return ".body"


def build_record(capture: RequestCapture, settings: Settings) -> dict[str, Any]:
    analysis = capture.analysis or Analysis()
    return {
        "schema": "php2shell-honeypot.event/1.0",
        "event": "http_request",
        "request_id": capture.request_id,
        "timestamp": capture.timestamp,
        "tls": capture.tls,
        "sensor": {
            "name": settings.server_name,
            "version": SENSOR_VERSION,
            "server_token": settings.server_token,
            "powered_by": settings.powered_by,
        },
        "client": {
            "ip": capture.client_ip,
            "port": capture.client_port,
        },
        "request": {
            "method": capture.method,
            "scheme": capture.scheme,
            "host": capture.host,
            "path": capture.path,
            "raw_path": capture.raw_path,
            "query": capture.query,
            "http_version": capture.http_version,
            "headers": [[name, value] for name, value in capture.headers],
            "header_count": capture.header_count,
            "header_bytes": capture.header_bytes,
            "duplicate_headers": capture.duplicate_headers,
            "content_type": capture.content_type,
            "declared_content_length": capture.declared_content_length,
            "transfer_encoding": capture.transfer_encoding,
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
        "form": {key: value[:512] for key, value in list(capture.form.items())[:20]},
        "query": {key: value[:512] for key, value in list(capture.query_params.items())[:20]},
        "analysis": analysis.to_dict(),
        "artifacts": [],
        "response": {
            "status": capture.status_code,
            "headers": capture.response_headers,
        },
        "error": capture.error,
    }


class ArtifactStore:
    """Append-only telemetry, payload quarantine and IOC feed writer."""

    def __init__(self, settings: Settings) -> None:
        self.settings = settings
        for directory in (settings.log_dir, settings.payload_dir, settings.tmp_dir):
            directory.mkdir(parents=True, exist_ok=True)
        self.log_path = settings.log_dir / "exploits.json"
        self.ioc_path = settings.log_dir / "iocs.txt"
        self.manifest_path = settings.payload_dir / "manifest.jsonl"
        self._lock = asyncio.Lock()
        self._ioc_keys = self._load_ioc_keys()
        self._payload_files: set[str] = set()
        self._initialise_files()

    def _initialise_files(self) -> None:
        if not self.ioc_path.exists():
            self.ioc_path.write_text(IOC_HEADER, encoding="utf-8")
        self.log_path.touch(exist_ok=True)
        self.manifest_path.touch(exist_ok=True)

    def _load_ioc_keys(self) -> set[tuple[str, str]]:
        keys: set[tuple[str, str]] = set()
        if not self.ioc_path.exists():
            return keys
        try:
            for line in self.ioc_path.read_text(encoding="utf-8", errors="replace").splitlines():
                if not line or line.startswith("#"):
                    continue
                columns = line.split("\t")
                if len(columns) >= 2:
                    keys.add((columns[0], columns[1]))
        except OSError:
            LOG.warning("could not read existing IOC file %s", self.ioc_path)
        return keys

    async def persist(self, capture: RequestCapture) -> None:
        try:
            async with self._lock:
                await asyncio.to_thread(self._persist_sync, capture)
        except Exception:  # telemetry must never break the response path
            LOG.exception("failed to persist telemetry for %s", capture.request_id)
        finally:
            capture.body.close()

    def _persist_sync(self, capture: RequestCapture) -> None:
        settings = self.settings
        analysis = capture.analysis or Analysis()
        record = build_record(capture, settings)

        if analysis.is_exploit:
            artifacts = self._save_artifacts(capture)
            record["artifacts"] = artifacts
            for artifact in artifacts:
                if artifact["kind"] == "request_body":
                    record["body"]["saved_as"] = artifact["file"]
                    break

        if analysis.is_exploit or settings.log_all_requests:
            with self.log_path.open("a", encoding="utf-8") as handle:
                handle.write(json.dumps(record, ensure_ascii=False, default=str) + "\n")

        if analysis.is_exploit:
            self._update_iocs(capture, analysis)

    def _save_artifacts(self, capture: RequestCapture) -> list[dict[str, Any]]:
        artifacts: list[dict[str, Any]] = []
        used = 0
        if capture.body_size:
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
            budget = self.settings.max_artifact_bytes
            for part in capture.multipart.parts:
                if saved_parts >= self.settings.max_artifact_parts or used >= budget:
                    break
                has_markers = bool(_webshell_markers(part.data))
                if not part.filename and not has_markers:
                    continue
                if part.size == 0 or not part.data:
                    continue
                data = part.data[: budget - used]
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
        filename = f"{capture.body_sha256}{_body_extension(capture)}"
        path = self.settings.payload_dir / filename
        written = min(capture.body.stored_bytes, self.settings.max_artifact_bytes)
        truncated = capture.body.truncated or written < capture.body.stored_bytes
        if filename not in self._payload_files and not path.exists():
            written = capture.body.save_to(path, self.settings.max_artifact_bytes)
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
        self._payload_files.add(filename)
        return filename, written, truncated

    def _save_part(
        self, capture: RequestCapture, part: MultipartPart, data: bytes
    ) -> str:
        filename = f"{part.sha256}{_part_extension(part)}"
        path = self.settings.payload_dir / filename
        truncated = part.truncated or len(data) < part.size
        if filename not in self._payload_files and not path.exists():
            path.write_bytes(data)
            self._append_manifest(
                {
                    "sha256": part.sha256,
                    "file": filename,
                    "kind": "uploaded_file" if part.filename else "payload_fragment",
                    "size": len(data),
                    "original_filename": part.filename,
                    "content_type": part.content_type,
                    "truncated": truncated,
                    "first_seen": capture.timestamp,
                    "request_id": capture.request_id,
                    "source_ip": capture.client_ip,
                }
            )
        self._payload_files.add(filename)
        return filename

    def _append_manifest(self, entry: dict[str, Any]) -> None:
        with self.manifest_path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(entry, ensure_ascii=False, default=str) + "\n")

    def _update_iocs(self, capture: RequestCapture, analysis: Analysis) -> None:
        context = f"{analysis.severity}:{','.join(analysis.cves) or 'generic'}:{capture.request_id}"
        lines: list[str] = []
        for kind, values in analysis.iocs.items():
            for value in values:
                cleaned = str(value).replace("\t", " ").replace("\n", " ").strip()
                if not cleaned:
                    continue
                key = (kind, cleaned)
                if key in self._ioc_keys:
                    continue
                self._ioc_keys.add(key)
                lines.append(
                    f"{kind}\t{cleaned}\t{capture.timestamp}\t{capture.timestamp}\t{context}\n"
                )
        if lines:
            with self.ioc_path.open("a", encoding="utf-8") as handle:
                handle.writelines(lines)


# --------------------------------------------------------------------------- #
# Telemetry middleware (raw body capture + TCP pacing observation)
# --------------------------------------------------------------------------- #
PHP_FATAL_500 = (
    "<!DOCTYPE html>\n<html><head><title>500 Internal Server Error</title></head><body>\n"
    "<h1>Internal Server Error</h1>\n"
    "<p>The server encountered an internal error or misconfiguration and was unable "
    "to complete your request.</p>\n"
    "<hr>\n<address>Apache/2.4.52 (Ubuntu) Server</address>\n</body></html>\n"
)


class TelemetryMiddleware:
    def __init__(
        self,
        app: ASGIApp,
        settings: Settings | None = None,
        store: ArtifactStore | None = None,
    ) -> None:
        self.app = app
        self.settings = settings or SETTINGS
        self.store = store or ArtifactStore(self.settings)

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        try:
            capture = await self._read_request(scope, receive)
        except Exception:
            LOG.exception("failed while reading request body")
            await send(
                {
                    "type": "http.response.start",
                    "status": 500,
                    "headers": [
                        (b"content-type", b"text/html; charset=UTF-8"),
                        (b"server", self.settings.server_token.encode()),
                    ],
                }
            )
            await send({"type": "http.response.body", "body": PHP_FATAL_500.encode()})
            return

        enrich_request(capture)
        capture.analysis = analyze(capture, self.settings)
        scope["honeypot.capture"] = capture

        replay_state = {"finished": False}

        async def replay() -> Message:
            chunk = capture.body.read_replay_chunk()
            if chunk:
                return {"type": "http.request", "body": chunk, "more_body": True}
            if not replay_state["finished"]:
                replay_state["finished"] = True
                return {"type": "http.request", "body": b"", "more_body": False}
            return {"type": "http.disconnect"}

        async def send_wrapper(message: Message) -> None:
            if message["type"] == "http.response.start":
                capture.response_started = True
                capture.status_code = int(message["status"])
                headers = MutableHeaders(scope=message)
                headers["Server"] = self.settings.server_token
                headers["X-Powered-By"] = self.settings.powered_by
                headers["X-Request-Id"] = capture.request_id
                if capture.body.truncated or capture.incomplete:
                    headers["Connection"] = "close"
                capture.response_headers = dict(headers)
            await send(message)

        try:
            await self.app(scope, replay, send_wrapper)
        except Exception as exc:  # keep the illusion of an Apache/PHP 500
            capture.error = f"{type(exc).__name__}: {exc}"[:2000]
            LOG.exception("honeypot handler failed for %s", capture.request_id)
            if not capture.response_started:
                try:
                    await send_wrapper(
                        {
                            "type": "http.response.start",
                            "status": 500,
                            "headers": [(b"content-type", b"text/html; charset=UTF-8")],
                        }
                    )
                    await send_wrapper(
                        {"type": "http.response.body", "body": PHP_FATAL_500.encode()}
                    )
                except Exception:
                    LOG.debug("client disconnected before 500 response", exc_info=True)
        finally:
            await self.store.persist(capture)

    async def _read_request(self, scope: Scope, receive: Receive) -> RequestCapture:
        settings = self.settings
        headers_raw = [
            (name.decode("latin-1", "replace"), value.decode("latin-1", "replace"))
            for name, value in scope.get("headers", [])
        ]
        header_map: dict[str, str] = {}
        counts: dict[str, int] = {}
        header_bytes = 0
        for name, value in headers_raw:
            key = name.lower()
            header_map[key] = f"{header_map[key]}, {value}" if key in header_map else value
            counts[key] = counts.get(key, 0) + 1
            header_bytes += len(name) + len(value) + 4
        duplicate_headers = sum(max(0, count - 1) for count in counts.values())

        declared: int | None = None
        raw_length = header_map.get("content-length", "").strip()
        if raw_length.isdigit():
            declared = int(raw_length)

        client = scope.get("client") or ("0.0.0.0", 0)
        client_ip = str(client[0]) if client else "0.0.0.0"
        client_port = client[1] if len(client) > 1 else None
        if settings.trust_proxy_headers:
            forwarded = header_map.get("x-forwarded-for", "")
            if forwarded:
                client_ip = forwarded.split(",")[0].strip()

        raw_path = scope.get("raw_path") or b""
        if isinstance(raw_path, bytes):
            raw_path_text = raw_path.decode("latin-1", "replace")
        else:  # pragma: no cover - ASGI spec says bytes
            raw_path_text = str(raw_path)

        capture = RequestCapture(
            request_id=uuid.uuid4().hex,
            timestamp=utc_now(),
            tls=scope.get("scheme") == "https",
            method=scope.get("method", "GET"),
            scheme=scope.get("scheme", "http"),
            host=header_map.get("host", ""),
            path=scope.get("path", "/"),
            raw_path=raw_path_text,
            query=scope.get("query_string", b"").decode("latin-1", "replace")[:8192],
            http_version=scope.get("http_version", "1.1"),
            client_ip=client_ip,
            client_port=client_port,
            headers=headers_raw,
            header_map=header_map,
            header_count=len(headers_raw),
            header_bytes=header_bytes,
            duplicate_headers=duplicate_headers,
            declared_content_length=declared,
            transfer_encoding=header_map.get("transfer-encoding", ""),
            body=BodySpool(settings.max_body_bytes, settings.tmp_dir),
        )
        await self._drain_body(capture, receive)
        return capture

    async def _drain_body(self, capture: RequestCapture, receive: Receive) -> None:
        """Stream the request body into the bounded spool, timing each chunk."""
        settings = self.settings
        started = time.monotonic()
        last_chunk_at: float | None = None

        while True:
            try:
                message = await asyncio.wait_for(
                    receive(), timeout=settings.body_timeout_seconds
                )
            except asyncio.TimeoutError:
                capture.timed_out = True
                capture.incomplete = True
                break
            except Exception:
                capture.incomplete = True
                break

            if message["type"] == "http.disconnect":
                capture.disconnected = True
                capture.incomplete = True
                break

            chunk = message.get("body", b"")
            now = time.monotonic()
            if chunk:
                if last_chunk_at is None:
                    capture.first_byte_seconds = now - started
                elif len(capture.chunk_gaps) < 2000:
                    capture.chunk_gaps.append(round(now - last_chunk_at, 4))
                last_chunk_at = now
                capture.chunk_count += 1
                capture.body.write(chunk, settings.probe_bytes)

            if not message.get("more_body", False):
                break
            if capture.body.truncated:
                capture.incomplete = True
                break

        capture.body_seconds = time.monotonic() - started
        if (
            capture.declared_content_length is not None
            and capture.body_size < capture.declared_content_length
            and not capture.body.truncated
        ):
            capture.incomplete = True


# --------------------------------------------------------------------------- #
# Deception surface
# --------------------------------------------------------------------------- #
TIMEOUT_PAGE = """<!DOCTYPE HTML PUBLIC "-//IETF//DTD HTML 2.0//EN">
<html><head>
<title>408 Request Timeout</title>
</head><body>
<h1>Request Timeout</h1>
<p>Server timeout waiting for the HTTP request from the client.</p>
<hr>
<address>Apache/2.4.52 (Ubuntu) Server</address>
</body></html>
"""


def _html_response(request: Request, body: str, status: int = 200) -> Response:
    capture = request.scope.get("honeypot.capture")
    if capture is not None and capture.timed_out:
        status = 408
        body = TIMEOUT_PAGE
    payload = body.encode("utf-8")
    headers = {
        "Content-Type": "text/html; charset=UTF-8",
        "Content-Length": str(len(payload)),
        "Accept-Ranges": "bytes",
    }
    if request.method == "HEAD":
        return Response(status_code=status, headers=headers)
    return Response(content=payload, status_code=status, headers=headers)


def index_page(settings: Settings) -> str:
    return f"""<!DOCTYPE html>
<html lang="en">
<head><meta charset="utf-8"><title>Acme Intranet &mdash; File Portal</title></head>
<body>
<h1>Acme Intranet File Portal</h1>
<p>Internal document exchange. Authorised users only.</p>
<form action="/upload.php" method="post" enctype="multipart/form-data">
  <label>Select file: <input type="file" name="file"></label>
  <input type="submit" value="Upload file">
</form>
<p>Server: {html.escape(settings.server_token)} &middot; PHP {html.escape(settings.php_version)}</p>
<ul>
  <li><a href="/uploads/">Uploaded files</a></li>
  <li><a href="/phpinfo.php">System information</a></li>
</ul>
<hr>
<address>Apache/2.4.52 (Ubuntu) Server at {html.escape(settings.server_name)} Port 80</address>
</body></html>
"""


def phpinfo_page(settings: Settings) -> str:
    rows = {
        "PHP Version": settings.php_version,
        "System": "Linux web01 5.15.0-91-generic #101-Ubuntu SMP x86_64",
        "Server API": "FPM/FastCGI",
        "Loaded Configuration File": "/etc/php/8.1/fpm/php.ini",
        "memory_limit": settings.memory_limit,
        "post_max_size": "128M",
        "upload_max_filesize": "128M",
        "max_file_uploads": "20",
        "max_input_vars": "1000",
        "session.upload_progress.enabled": "On",
        "session.upload_progress.cleanup": "On",
        "session.upload_progress.prefix": "upload_progress_",
        "session.save_path": "/var/lib/php/sessions",
        "allow_url_include": "Off",
        "disable_functions": "exec,passthru,shell_exec,system",
    }
    body = "\n".join(
        f'<tr><td class="e">{html.escape(key)}</td><td class="v">{html.escape(value)}</td></tr>'
        for key, value in rows.items()
    )
    return f"""<!DOCTYPE html>
<html><head><meta charset="utf-8"><title>phpinfo()</title></head>
<body>
<h1>PHP Version {html.escape(settings.php_version)}</h1>
<table>
<tr><td>Server API</td><td>FPM/FastCGI</td></tr>
{body}
</table>
<hr>
<address>Apache/2.4.52 (Ubuntu) Server at {html.escape(settings.server_name)}</address>
</body></html>
"""


UPLOADS_PAGE = """<!DOCTYPE html>
<html><head><meta charset="utf-8"><title>Index of /uploads</title></head>
<body>
<h1>Index of /uploads</h1>
<pre>
<a href="../">../</a>
<a href="quarterly-report.pdf">quarterly-report.pdf</a>        2026-09-14 09:21   412K
<a href="backup-2026-09.tar.gz">backup-2026-09.tar.gz</a>        2026-09-30 23:02   8.4M
<a href="onboarding.docx">onboarding.docx</a>              2026-10-02 11:47   184K
<a href="logo.png">logo.png</a>                     2026-08-19 15:33    27K
</pre>
<address>Apache/2.4.52 (Ubuntu) Server</address>
</body></html>
"""


SERVER_STATUS_PAGE = """<!DOCTYPE html>
<html><head><title>Apache Server Status</title></head>
<body>
<h1>Apache Server Status for localhost</h1>
<dl>
<dt>Server Version: Apache/2.4.52 (Ubuntu) OpenSSL/3.0.2</dt>
<dt>Server MPM: event</dt>
<dt>Server Built: 2024-01-24T14:22:01</dt>
<dt>Current Time: __TIME__</dt>
<dt>Restart Time: __TIME__</dt>
<dt>Parent Server Config. Generation: 3</dt>
<dt>Total accesses: 18422 - Total Traffic: 91.4 MB</dt>
<dt>2 requests currently being processed, 6 idle workers</dt>
</dl>
<pre>__SCOREBOARD__</pre>
</body></html>
"""


WP_LOGIN_PAGE = """<!DOCTYPE html>
<html lang="en-US"><head><meta charset="UTF-8"><title>Log In &lsaquo; Acme &mdash; WordPress</title></head>
<body class="login">
<div id="login"><h1><a href="/">Acme</a></h1>
<form name="loginform" id="loginform" action="/wp-login.php" method="post">
<p><label for="user_login">Username or Email Address</label>
<input type="text" name="log" id="user_login"></p>
<p><label for="user_pass">Password</label>
<input type="password" name="pwd" id="user_pass"></p>
<p class="submit"><input type="submit" name="wp-submit" id="wp-submit" value="Log In"></p>
</form>
<p id="nav"><a href="/wp-login.php?action=lostpassword">Lost your password?</a></p>
</div>
</body></html>
"""


LOGIN_FAILED_PAGE = """<!DOCTYPE html>
<html lang="en-US"><head><meta charset="UTF-8"><title>Log In &lsaquo; Acme &mdash; WordPress</title></head>
<body class="login">
<div id="login"><h1><a href="/">Acme</a></h1>
<div id="login_error"><strong>Error:</strong> The password you entered for the username is incorrect.</div>
<form name="loginform" id="loginform" action="/wp-login.php" method="post">
<p><label for="user_login">Username or Email Address</label>
<input type="text" name="log" id="user_login"></p>
<p><label for="user_pass">Password</label>
<input type="password" name="pwd" id="user_pass"></p>
<p class="submit"><input type="submit" name="wp-submit" id="wp-submit" value="Log In"></p>
</form>
</div>
</body></html>
"""


def oom_page(settings: Settings) -> str:
    return f"""<br />
<b>Fatal error</b>:  Allowed memory size of 134217728 bytes exhausted (tried to allocate 40960 bytes) in <b>/var/www/html/upload.php</b> on line <b>17</b><br />
<br />
<b>Fatal error</b>:  Uncaught Error: Allowed memory size exhausted while parsing multipart body in /var/www/html/upload.php:21
Stack trace:
#0 {{main}}
  thrown in <b>/var/www/html/upload.php</b> on line <b>21</b><br />
<address>Apache/2.4.52 (Ubuntu) Server at {html.escape(settings.server_name)} Port 80</address>
"""


SESSION_UPLOAD_PAGE = """<!DOCTYPE html>
<html><head><meta charset="utf-8"><title>Upload complete</title></head>
<body>
<p>Upload completed successfully.</p>
<!-- session.upload_progress: request handled by upload progress callback -->
<address>Apache/2.4.52 (Ubuntu) Server</address>
</body></html>
"""


def upload_success_page(filename: str) -> str:
    safe = html.escape(filename) if filename else "unnamed"
    return f"""<!DOCTYPE html>
<html><head><meta charset="utf-8"><title>Upload complete</title></head>
<body>
<h1>Upload complete</h1>
<p>The file <strong>{safe}</strong> has been uploaded to <code>/uploads/</code>.</p>
<p><a href="/uploads/">Return to uploads</a></p>
<address>Apache/2.4.52 (Ubuntu) Server</address>
</body></html>
"""


def not_found_page(settings: Settings, path: str) -> str:
    return f"""<!DOCTYPE HTML PUBLIC "-//IETF//DTD HTML 2.0//EN">
<html><head>
<title>404 Not Found</title>
</head><body>
<h1>Not Found</h1>
<p>The requested URL {html.escape(path[:300])} was not found on this server.</p>
<hr>
<address>Apache/2.4.52 (Ubuntu) Server at {html.escape(settings.server_name)} Port 80</address>
</body></html>
"""


def method_not_allowed_page(method: str) -> str:
    return f"""<!DOCTYPE HTML PUBLIC "-//IETF//DTD HTML 2.0//EN">
<html><head>
<title>405 Method Not Allowed</title>
</head><body>
<h1>Method Not Allowed</h1>
<p>The requested method {html.escape(method)} is not allowed for this URL.</p>
<hr>
<address>Apache/2.4.52 (Ubuntu) Server</address>
</body></html>
"""


# --------------------------------------------------------------------------- #
# FastAPI application
# --------------------------------------------------------------------------- #
STORE = ArtifactStore(SETTINGS)

app = FastAPI(
    title="Acme Intranet",
    docs_url=None,
    redoc_url=None,
    openapi_url=None,
    debug=False,
)
app.add_middleware(TelemetryMiddleware, settings=SETTINGS, store=STORE)


def _capture(request: Request) -> RequestCapture | None:
    return request.scope.get("honeypot.capture")


def upload_response(request: Request) -> Response:
    capture = _capture(request)
    analysis = capture.analysis if capture else Analysis()

    if "CVE-2026-109618" in analysis.cves:
        return _html_response(request, oom_page(SETTINGS), status=500)

    if "CVE-2026-109619" in analysis.cves:
        return _html_response(
            request,
            SESSION_UPLOAD_PAGE,
            status=200,
        )

    filename = ""
    if capture and capture.multipart and capture.multipart.file_parts:
        filename = capture.multipart.file_parts[0].filename or ""
    return _html_response(request, upload_success_page(filename), status=200)


@app.api_route("/", methods=["GET", "HEAD"])
@app.api_route("/index.php", methods=["GET", "HEAD"])
@app.api_route("/index.html", methods=["GET", "HEAD"])
async def index(request: Request) -> Response:
    return _html_response(request, index_page(SETTINGS))


@app.api_route("/phpinfo.php", methods=["GET", "HEAD"])
async def phpinfo(request: Request) -> Response:
    return _html_response(request, phpinfo_page(SETTINGS))


@app.api_route("/uploads", methods=["GET", "HEAD"])
@app.api_route("/uploads/", methods=["GET", "HEAD"])
async def uploads(request: Request) -> Response:
    return _html_response(request, UPLOADS_PAGE)


@app.api_route("/server-status", methods=["GET", "HEAD"])
async def server_status(request: Request) -> Response:
    timestamp = datetime.now(timezone.utc).strftime("%a %b %d %H:%M:%S %Y")
    page = SERVER_STATUS_PAGE.replace("__TIME__", timestamp).replace(
        "__SCOREBOARD__", "_" * 120
    )
    return _html_response(request, page)


@app.api_route("/upload.php", methods=["POST", "PUT", "PATCH"])
async def upload_endpoint(request: Request) -> Response:
    return upload_response(request)


@app.api_route("/wp-login.php", methods=["GET", "HEAD", "POST"])
async def wp_login(request: Request) -> Response:
    if request.method == "POST":
        return _html_response(request, LOGIN_FAILED_PAGE, status=200)
    return _html_response(request, WP_LOGIN_PAGE)


@app.api_route("/robots.txt", methods=["GET", "HEAD"])
async def robots(request: Request) -> Response:
    return Response(
        content="User-agent: *\nDisallow: /uploads/\nDisallow: /admin/\n",
        media_type="text/plain",
    )


@app.api_route("/healthz", methods=["GET", "HEAD"])
async def healthz() -> JSONResponse:
    return JSONResponse({"status": "ok"})


@app.api_route(
    "/{full_path:path}",
    methods=["GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "TRACE"],
)
async def catch_all(request: Request, full_path: str) -> Response:
    capture = _capture(request)
    method = request.method.upper()
    path = "/" + full_path

    if method == "OPTIONS":
        return Response(
            status_code=200,
            headers={
                "Allow": "GET,HEAD,POST,PUT,DELETE,OPTIONS,TRACE",
                "Content-Length": "0",
            },
        )
    if method == "TRACE":
        return _html_response(request, method_not_allowed_page(method), status=405)
    if method == "DELETE":
        return _html_response(request, not_found_page(SETTINGS, path), status=404)
    if method in {"POST", "PUT", "PATCH"}:
        is_php = path.endswith((".php", ".phtml", ".php5", ".php7"))
        if is_php or (capture and (capture.multipart or capture.form)):
            return upload_response(request)
    return _html_response(request, not_found_page(SETTINGS, path), status=404)


@app.exception_handler(StarletteHTTPException)
async def http_exception_handler(request: Request, exc: StarletteHTTPException) -> Response:
    if exc.status_code == 404:
        return _html_response(request, not_found_page(SETTINGS, request.url.path), 404)
    if exc.status_code == 405:
        return _html_response(request, method_not_allowed_page(request.method), 405)
    return _html_response(
        request,
        f"<h1>{exc.status_code} {html.escape(str(exc.detail))}</h1>",
        exc.status_code,
    )


@app.exception_handler(Exception)
async def unhandled_exception_handler(request: Request, exc: Exception) -> Response:
    LOG.exception("unhandled honeypot exception: %s", exc)
    return _html_response(request, PHP_FATAL_500, status=500)


# --------------------------------------------------------------------------- #
# Server entrypoint
# --------------------------------------------------------------------------- #
def _uvicorn_config(port: int, tls: bool = False) -> uvicorn.Config:
    options: dict[str, Any] = {
        "app": app,
        "host": SETTINGS.host,
        "port": port,
        "log_level": _env_str("HONEYPOT_UVICORN_LOG_LEVEL", "warning"),
        "access_log": False,
        "server_header": False,
        "proxy_headers": False,
        "timeout_keep_alive": 15,
        "lifespan": "on",
    }
    if tls:
        options["ssl_certfile"] = str(SETTINGS.cert_file)
        options["ssl_keyfile"] = str(SETTINGS.key_file)
    return uvicorn.Config(**options)


async def serve_async() -> None:
    servers: list[uvicorn.Server] = [uvicorn.Server(_uvicorn_config(SETTINGS.http_port))]

    if SETTINGS.enable_tls:
        if not (SETTINGS.cert_file.exists() and SETTINGS.key_file.exists()):
            raise SystemExit(
                f"HONEYPOT_TLS is enabled but certificate files are missing: "
                f"{SETTINGS.cert_file} / {SETTINGS.key_file}"
            )
        tls_server = uvicorn.Server(_uvicorn_config(SETTINGS.https_port, tls=True))
        # Only the primary server owns signal handling; the TLS listener shares it.
        tls_server.install_signal_handlers = lambda: None  # type: ignore[method-assign]
        servers.append(tls_server)

    banner = (
        "PHP2Shell honeypot listening on "
        f"http://{SETTINGS.host}:{SETTINGS.http_port}"
    )
    if SETTINGS.enable_tls:
        banner += f" and https://{SETTINGS.host}:{SETTINGS.https_port}"
    LOG.info(banner)
    LOG.info(
        "telemetry -> %s | payloads -> %s | iocs -> %s",
        STORE.log_path,
        SETTINGS.payload_dir,
        STORE.ioc_path,
    )
    print(banner, flush=True)

    await asyncio.gather(*(server.serve() for server in servers))


def main() -> None:
    logging.basicConfig(
        level=_env_str("HONEYPOT_LOG_LEVEL", "INFO").upper(),
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )
    try:
        asyncio.run(serve_async())
    except KeyboardInterrupt:  # pragma: no cover - interactive shutdown
        pass


if __name__ == "__main__":
    main()
