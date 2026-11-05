"""Detection engine: classify a captured request against PHP2Shell signatures.

Only bounded request metadata and the in-memory probe prefix are inspected;
nothing is ever handed to an interpreter.
"""
from __future__ import annotations

import re
from typing import Any
from urllib.parse import urlsplit

from .capture import Analysis, RequestCapture, Signal
from .config import Config
from .parsing import find_webshell_markers, parse_content_type

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

SENSITIVE_PATHS = {
    "/.env",
    "/.git/config",
    "/wp-config.php",
    "/config.php",
    "/phpinfo.php",
    "/server-status",
    "/shell.php",
}


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
    return find_webshell_markers(data)


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


def analyze(capture: RequestCapture, cfg: Config) -> Analysis:
    cfgd = cfg.detection
    analysis = Analysis()
    mime, _ = parse_content_type(capture.content_type)
    is_multipart = mime == "multipart/form-data"
    method = capture.method.upper()
    probe = capture.body_probe
    probe_lower = probe[: 512 * 1024].lower()
    mp = capture.multipart

    if capture.client_ip:
        analysis.add_ioc("ip", capture.client_ip)

    # CVE-2026-109618: memory-exhaustion multipart / mangled framing.
    if is_multipart and method in {"POST", "PUT", "PATCH"}:
        if capture.body_size >= cfgd.large_multipart_bytes:
            _add_signal(
                analysis,
                "large_multipart_upload",
                "high",
                "Multipart upload exceeds the PHP2Shell OOM trigger threshold",
                "CVE-2026-109618",
                body_bytes=capture.body_size,
                threshold_bytes=cfgd.large_multipart_bytes,
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

        if len(mp.parts) >= cfgd.many_parts:
            _add_signal(
                analysis,
                "excessive_multipart_parts",
                "high",
                "Multipart body contains an abusive number of parts",
                "CVE-2026-109618",
                part_count=len(mp.parts),
                threshold=cfgd.many_parts,
            )
        if mp.max_header_size >= cfgd.part_header_bytes:
            _add_signal(
                analysis,
                "oversized_part_headers",
                "high",
                "Multipart part headers exceed normal PHP parser limits",
                "CVE-2026-109618",
                max_header_bytes=mp.max_header_size,
                threshold=cfgd.part_header_bytes,
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
        if declared > cfg.storage.max_body_bytes:
            _add_signal(
                analysis,
                "content_length_overflow",
                "high",
                "Declared Content-Length far exceeds safe PHP request limits",
                "CVE-2026-109618",
                declared_content_length=declared,
                capture_cap=cfg.storage.max_body_bytes,
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

    if capture.header_count >= cfgd.header_count or capture.header_bytes >= cfgd.header_bytes:
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

    # CVE-2026-109619: PHP_SESSION_UPLOAD_PROGRESS and paused TCP streams.
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

    if capture.max_chunk_gap >= cfgd.slow_gap_seconds:
        _add_signal(
            analysis,
            "tcp_stream_pause",
            "high",
            "Attacker deliberately paused the TCP stream mid-upload",
            "CVE-2026-109619",
            max_chunk_gap_seconds=round(capture.max_chunk_gap, 3),
            threshold_seconds=cfgd.slow_gap_seconds,
            chunk_count=capture.chunk_count,
        )
    if capture.body_seconds >= cfgd.slow_total_seconds and capture.body_size > 0:
        _add_signal(
            analysis,
            "slow_body_delivery",
            "high",
            "Request body delivered slowly over an extended window",
            "CVE-2026-109619",
            body_seconds=round(capture.body_seconds, 3),
            threshold_seconds=cfgd.slow_total_seconds,
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
            timeout_seconds=cfg.storage.body_timeout_seconds,
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
            capture_cap=cfg.storage.max_body_bytes,
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

    # Generic tradecraft.
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

    if capture.path in SENSITIVE_PATHS:
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

    # IOC harvesting (bounded, deduplicated).
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
