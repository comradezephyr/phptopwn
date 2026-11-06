# Changelog

All notable changes to `phptopwn` are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses
[Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added

- Fleet relay: sensor-side store-and-forward shipping of `phptopwn.event/1.0`
  records to a regional collector (`[fleet]` config section, outbox ring
  buffer with drop-oldest overflow, byte-offset resume across restarts,
  worker thread, live counters). No sensor egress except the collector URL.
- Regional collector (`phptopwn-collect serve`): NDJSON ingest at
  `/v1/events` with per-line validation and partial-accept reporting,
  constant-time bearer-token check, node allowlist (`[nodes]`, authoritative
  region attribution), per-IP ingest rate limit, bounded dedupe window,
  day-partitioned append-only raw store, hardening headers.
- Daily IOC export (`phptopwn-collect ioc`): per-IP and payload-hash
  aggregation per raw day, JSON + CSV artefacts with a SHA-256 manifest.
- Fleet dashboard (loopback HTML pages): recent-day overview, region
  composition, recent events; no external assets, no scripts.
- `docs/SCHEMA.md` (event + ingest contract) and `docs/FLEET.md` (runbook,
  egress lockdown, preflight gates, governance rules).

### Changed

- `SENSOR_VERSION` now follows `phptopwn.__version__` (event records carry
  the running sensor version).
- Coverage gate stays at 85%; fleet/collector/IOC/dashboard modules are
  covered by new test suites (`tests/test_fleet.py`,
  `tests/test_collector.py`).

## [1.0.0] - 2026-11-06

First tagged release of the PHP2Shell honeypot sensor.

### Added

- High-interaction decoy surface: Acme Intranet file portal with Apache
  2.4.52 / PHP-FPM 8.1.2 wire fingerprints (`Server`, `X-Powered-By`,
  decoy phpinfo / wp-login / server-status / directory listing pages) and
  Apache-style 404/405/408 handling.
- Coverage of the PHP2Shell exploitation family: CVE-2026-109618
  (oversized / mangled multipart, OOM bait) and CVE-2026-109619
  (`PHP_SESSION_UPLOAD_PROGRESS` session-file poisoning, TCP pause races).
- Safe HTTP pipeline: non-PHP multipart parser, bounded bodies
  (`SpooledTemporaryFile` + capture cap), stalled-upload read timeout, and
  simulated PHP responses instead of any interpreter execution.
- Source guard: per-IP rate limiting, concurrency cap and header-flood
  rejection, each counted in metrics and persisted as minimal records.
- Quarantine layer: SHA-256-named inert artifacts with neutralized `.bin`
  extensions, append-only `manifest.jsonl`, deduplication and size caps.
- IOC feed (`logs/iocs.txt`): IP / SHA-256 / URL / domain / filename
  extraction with deduplication over restarts.
- JSON Lines telemetry (`logs/exploits.json`, `phptopwn.event/1.0`) with
  request headers, multipart structure, chunk pacing, signals + evidence and
  response status.
- Detection scoring with severity ranking, CVE attribution and generic
  tradecraft signals (droppers, webshell markers, scanner user agents).
- Internal listener: `/healthz` status payload and Prometheus `/metrics`
  exposition covering requests, guards, signatures, alerts and talkers.
- Webhook alerting with severity gating, per-IP cooldown metering, inflight
  cap and sent/failed/accounting metrics — never request-blocking.
- Structured JSON operational logging (single object per line, GMT stamps).
- Filesystem retention sweeps: age/count pruning for captures, size-triggered
  log rotation with archive bookkeeping.
- Packaging: pip-installable `phptopwn` package with pinned fastapi/uvicorn/
  prometheus-client/httpx, `phptopwn` console script, `--dry-run` and
  `--version`.
- Multi-stage Dockerfile (python:3.12-slim, non-root, wheel-only runtime),
  hardened docker-compose (read-only rootfs, dropped capabilities, CPU/PID/
  memory caps, loopback-only metrics publish), and a sandboxed systemd unit
  with example environment file.
- Test suite: 124 pytest unit tests with an 85% branch-coverage gate,
  stdlib-only end-to-end smoke test, ruff and mypy gates, and a GitHub
  Actions CI workflow running all three.
- Full configuration reference (`docs/CONFIG.md`), README, CHANGELOG and MIT
  license.

### Safety notes

- The sensor never writes executable content to paths consumed by a PHP
  runtime: quarantined captures are neutralized by default and are never
  served, executed or interpreted.
- Responses are generated from static templates; no attacker byte reaches an
  interpreter, a subprocess or a shell.
