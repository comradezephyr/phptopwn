"""Captured request model: bounded body spool, multipart structure, verdicts."""
from __future__ import annotations

import hashlib
import tempfile
from dataclasses import dataclass, field
from typing import Any

SEVERITY_RANK = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


@dataclass
class BodySpool:
    """Bounded body capture: in-memory probe prefix plus a spooled tail copy."""

    max_bytes: int
    hash: Any = field(init=False)
    size: int = 0
    stored_bytes: int = 0
    truncated: bool = False
    probe: bytearray = field(default_factory=bytearray)
    _spool: Any = field(init=False)
    _replay_started: bool = field(init=False, default=False)
    _replay_finished: bool = field(init=False, default=False)

    def __post_init__(self) -> None:
        self.hash = hashlib.sha256()
        self._spool = tempfile.SpooledTemporaryFile(
            max_size=1024 * 1024, prefix="phptopwn-body-", suffix=".spool"
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

    def save_to(self, path: Any, limit: int | None = None) -> int:
        try:
            self._spool.seek(0)
        except (OSError, ValueError):
            return 0
        remaining = self.stored_bytes if limit is None else max(0, min(limit, self.stored_bytes))
        written = 0
        with open(path, "wb") as handle:
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
        except Exception:  # defensive close; the spool may already be gone
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
        if not value:
            return
        bucket = self.iocs.setdefault(kind, [])
        if value not in bucket:
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
