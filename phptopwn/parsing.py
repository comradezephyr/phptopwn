"""Pure parsers: content types, multipart bodies, query/form fields."""
from __future__ import annotations

import hashlib
import re
from typing import Any
from urllib.parse import parse_qsl, unquote

from .capture import MultipartPart, MultipartResult

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
    pattern = re.compile(
        r"""\bfilename\s*=\s*(?:"((?:[^"\\]|\\.)*)"|'([^']*)'|([^;\s]+))""",
        re.IGNORECASE,
    )
    match = pattern.search(disposition)
    if not match:
        return None
    raw = next((group for group in match.groups() if group is not None), "")
    return raw.replace('\\"', '"').replace("\\\\", "\\")


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
    """Split a multipart body without handing anything to an interpreter."""
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
            # A boundary flood must not turn into unbounded parser work.
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
            # Bytes directly after a boundary: mangled framing.
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
        name = _disposition_param(disposition, "name")
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


def _disposition_param(value: str, key: str) -> str | None:
    pattern = re.compile(
        rf"""\b{key}\s*=\s*(?:"((?:[^"\\]|\\.)*)"|'([^']*)'|([^;\s]+))""",
        re.IGNORECASE,
    )
    match = pattern.search(value)
    if not match:
        return None
    raw = next((group for group in match.groups() if group is not None), "")
    return raw.replace('\\"', '"').replace("\\\\", "\\")


def find_webshell_markers(data: bytes) -> list[str]:
    lowered = data.lower()
    return [marker.decode("latin-1") for marker in _MARKER_BYTES if marker in lowered]


_MARKER_BYTES: list[bytes] = [
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


def enrich_capture(capture: Any) -> None:
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
