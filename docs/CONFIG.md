# phptopwn configuration reference

Configuration is a TOML file (default `phptopwn.toml` in the working
directory). Every field has a matching environment variable
`PHPTOPWN_<FIELD>` named after the field, for example
`storage.max_body_bytes` → `PHPTOPWN_MAX_BODY_BYTES`. A handful of frequent
switches have shorter aliases (marked **alias** below).

**Precedence:** built-in defaults < TOML file < environment < CLI flags
(`--host`, `--port`). Unknown TOML sections, unknown fields and out-of-range
values are rejected at startup with a `[phptopwn]:` configuration error — the
sensor refuses to start rather than guess.

Validate any configuration without starting the sensor:

```bash
phptopwn --dry-run                       # default discovery order
phptopwn --dry-run --config /etc/phptopwn/phptopwn.toml
```

The `[sensor]` block selects the listener and decoy identity:

| Field | Env variable | Default | Notes |
| --- | --- | --- | --- |
| `host` | `PHPTOPWN_HOST` | `0.0.0.0` | Bind address; must not be empty |
| `http_port` | `PHPTOPWN_HTTP_PORT` | `8080` | 1–65535, must differ from all other ports |
| `tls_port` | `PHPTOPWN_TLS_PORT` | `8443` | 1–65535 |
| `tls_enabled` | `PHPTOPWN_TLS` **(alias)** | `false` | Start the TLS listener in the same process |
| `cert_file` | `PHPTOPWN_CERT_FILE` | `certs/honeypot.crt` | PEM; must exist when TLS is on (`MissingCertificate` otherwise) |
| `key_file` | `PHPTOPWN_KEY_FILE` | `certs/honeypot.key` | PEM private key; must exist when TLS is on |
| `trust_proxy_headers` | `PHPTOPWN_TRUST_PROXY_HEADERS` | `false` | Only behind a proxy that overwrites `X-Forwarded-For`; attackers spoof it otherwise |
| `client_ip_header` | `PHPTOPWN_CLIENT_IP_HEADER` | `""` | Header whose value becomes the effective `client.ip` (e.g. `CF-Connecting-IP` behind a Cloudflare tunnel); raw TCP peer always kept in `client.peer_ip`. Only enable when all traffic arrives via the edge that writes the header |

Select an alternate file with `--config PATH` or
`PHPTOPWN_CONFIG=/path/to/phptopwn.toml`.

**Command line:** `--config`, `--host`, `--port`, `--dry-run`, `--version`.
`--host`/`--port` win over the environment; they exist for quick experiments,
prefer the file for anything durable.

Limits enforced by the source guard before any parsing happens:

| Field | Env variable | Default | Validation |
| --- | --- | --- | --- |
| `max_concurrency` | `PHPTOPWN_MAX_CONCURRENCY` | `200` | `>= 0`; `0` disables (uvicorn gets no concurrency cap) |
| `max_concurrent_per_ip` | `PHPTOPWN_MAX_CONCURRENT_PER_IP` | `32` | `>= 0`; `0` disables |
| `rate_limit_per_minute` | `PHPTOPWN_RATE_LIMIT_PER_MINUTE` | `600` | `>= 0`; `0` disables |
| `max_request_headers` | `PHPTOPWN_MAX_REQUEST_HEADERS` | `128` | `>= 8`; excess → immediate `400`, counted as `header_flood` |
| `max_header_bytes` | `PHPTOPWN_MAX_HEADER_BYTES` | `32768` | `>= 1024` |

Rejection semantics: `rate_limit_per_minute` and `max_concurrent_per_ip`
produce Apache-style **403** pages; `max_request_headers` / oversized header
blocks produce **400**. Every rejection is metered in Prometheus under
`phptopwn_guard_rejections{reason=...}` and persisted as a minimal capture
record (`"error": "<reason>"`, zero-byte body).

Bounded reads and quarantine behaviour:

| Field | Env variable | Default | Validation |
| --- | --- | --- | --- |
| `log_dir` | `PHPTOPWN_LOG_DIR` | `logs` | Created on first persist |
| `capture_dir` | `PHPTOPWN_CAPTURE_DIR` | `captured_payloads` | Created on first persist |
| `max_body_bytes` | `PHPTOPWN_MAX_BODY_BYTES` | `33554432` (32 MiB) | `>= 1024`; `probe_bytes`/`max_artifact_bytes` must not exceed it |
| `probe_bytes` | `PHPTOPWN_PROBE_BYTES` | `2097152` (2 MiB) | In-memory analysis window |
| `max_artifact_bytes` | `PHPTOPWN_MAX_ARTIFACT_BYTES` | `4194304` (4 MiB) | Per-artifact write cap |
| `max_artifact_parts` | `PHPTOPWN_MAX_ARTIFACT_PARTS` | `8` | 1–64 uploaded parts quarantined per request |
| `body_timeout_seconds` | `PHPTOPWN_BODY_TIMEOUT_SECONDS` | `30.0` | `>= 0.2`; stall past this → `408` + `body_read_timeout` signal |
| `neutralize_capture_names` | `PHPTOPWN_NEUTRALIZE_CAPTURE_NAMES` | `true` | Store uploads as `<sha256>.bin`; set `false` only if a downstream tool requires real extensions |

Filesystem retention sweeps (handled by the internal maintenance loop):

| Field | Env variable | Default | Validation |
| --- | --- | --- | --- |
| `max_capture_files` | `PHPTOPWN_MAX_CAPTURE_FILES` | `5000` | `>= 1`; oldest removed beyond the cap |
| `max_age_days` | `PHPTOPWN_MAX_AGE_DAYS` | `30` | `>= 1` |
| `max_log_bytes` | `PHPTOPWN_MAX_LOG_BYTES` | `52428800` (50 MiB) | `>= 1024`; oversized logs rotate to `<name>.<timestamp>` |
| `max_log_archives` | `PHPTOPWN_MAX_LOG_ARCHIVES` | `5` | `>= 0`; `0` drops history instead of archiving |
| `sweep_interval_seconds` | `PHPTOPWN_SWEEP_INTERVAL_SECONDS` | `600` | `>= 5` |

CVE-2026-109618 / CVE-2026-109619 detection thresholds:

| Field | Env variable | Default | Validation |
| --- | --- | --- | --- |
| `large_multipart_bytes` | `PHPTOPWN_LARGE_MULTIPART_BYTES` | `1048576` (1 MiB) | `>= 256`; `large_multipart_upload` signal |
| `many_parts` | `PHPTOPWN_MANY_PARTS` | `32` | `>= 2`; `excessive_multipart_parts` signal |
| `part_header_bytes` | `PHPTOPWN_PART_HEADER_BYTES` | `4096` | `>= 128`; `oversized_part_headers` signal |
| `header_count` | `PHPTOPWN_HEADER_COUNT` | `60` | `>= 5`; `header_flooding` signal |
| `header_bytes` | `PHPTOPWN_HEADER_BYTES` | `16384` | `>= 512`; `header_flooding` signal |
| `slow_gap_seconds` | `PHPTOPWN_SLOW_GAP_SECONDS` | `2.0` | `>= 0.01`; `tcp_stream_pause` signal |
| `slow_total_seconds` | `PHPTOPWN_SLOW_TOTAL_SECONDS` | `5.0` | `>= 0.01`; `slow_body_delivery` signal |
| `log_all_requests` | `PHPTOPWN_LOG_ALL` **(alias)** | `true` | Log benign traffic to `exploits.json` too |

Webhook alerting (POSTs one JSON object per exploit, never request-blocking):

| Field | Env variable | Default | Validation |
| --- | --- | --- | --- |
| `webhook_url` | `PHPTOPWN_WEBHOOK_URL` | *(empty → alerts off)* | any URL accepted by httpx |
| `min_severity` | `PHPTOPWN_MIN_SEVERITY` | `high` | one of `info`, `low`, `medium`, `high`, `critical` |
| `cooldown_seconds` | `PHPTOPWN_COOLDOWN_SECONDS` | `60.0` | `>= 0`; per source IP |
| `timeout_seconds` | `PHPTOPWN_TIMEOUT_SECONDS` | `5.0` | HTTP request timeout |
| `max_inflight` | `PHPTOPWN_MAX_INFLIGHT` | `8` | `>= 1`; overflows are counted, not queued |

The cooldown window opens **when an alert dispatches**; further hits arriving
inside the window are counted (`alerts_metered`) but never refresh it, so an
ongoing attack keeps alerting once per cooldown period.

Decoy surface identity:

| Field | Env variable | Default |
| --- | --- | --- |
| `server_token` | `PHPTOPWN_SERVER_TOKEN` | `Apache/2.4.52 (Ubuntu)` |
| `powered_by` | `PHPTOPWN_POWERED_BY` | `PHP/8.1.2` |
| `php_version` | `PHPTOPWN_PHP_VERSION` | `8.1.2` |
| `memory_limit` | `PHPTOPWN_MEMORY_LIMIT` | `128M` |
| `server_name` | `PHPTOPWN_SERVER_NAME` | `intranet.acme.local` |

Internal listener (`/healthz`, `/metrics`):

| Field | Env variable | Default | Notes |
| --- | --- | --- | --- |
| `metrics_host` | `PHPTOPWN_METRICS_HOST` | `127.0.0.1` | Bind `0.0.0.0` for container deployments |
| `metrics_port` | `PHPTOPWN_METRICS_PORT` | `9091` | Must differ from the sensor ports |

Operational logging (uvicorn access logs are disabled; all lines flow through
the root handler):

| Field | Env variable | Default |
| --- | --- | --- |
| `level` | `PHPTOPWN_LOG_LEVEL` **(alias)** | `INFO` |
| `json` | `PHPTOPWN_LOG_JSON` **(alias)** | `true` (one JSON object per line) |

Environment-only booleans accept `1/true/yes/on` (case-insensitive) and
`treat empty strings as unset`. Integer fields accept plain base-10 strings
and reject anything else.

Alert delivery is off until `PHPTOPWN_WEBHOOK_URL` is set. The webhook
receives a JSON POST shaped like:

```json
{
  "sensor": "phptopwn",
  "request_id": "3b0d2b73aa8f4db89a26fb42d8f00cdd",
  "timestamp": "2026-11-06T09:48:44.890Z",
  "client_ip": "203.0.113.77",
  "method": "POST",
  "path": "/upload.php",
  "severity": "high",
  "cves": ["CVE-2026-109619"],
  "signals": ["php_session_upload_progress", "command_dropper"],
  "iocs": {"ip": ["203.0.113.77"], "sha256": ["..."]}
}
```

Statuses 2xx increment `alerts_sent`; everything else (including transport
errors) increments `alerts_failed` and is logged at WARNING with the request id.
