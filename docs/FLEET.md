# Fleet runbook: sensors → regional collector

One collector per deployment region; N sensors per collector. The collector is
a distinct service with its own host, token and data directory — it is not
co-hosted with a honeypot sensor.

```
sensor (VPS, in-scope)  --HTTPS POST /v1/events-->  collector (VPS, private)
        outbox.jsonl                        raw/<day>.jsonl + ids/<day>.ids
        forwarder_state.json                dashboard (SSH tunnel only)
```

## Security posture

- Sensor egress: every sensor ships events to exactly one collector URL.
  Nothing else — no third-party reporting, no telemetry, no DNS-based
  beacons from the sensor software. Enforce with a host firewall so a
  compromised sensor cannot exfiltrate sideways:
  `ufw default deny outgoing && ufw allow out to <collector_ip> port 9443 proto tcp`.
- Collector ingress: allow only the sensor IPs (or their NAT range) on the
  ingest port. Dashboard is loopback-bound; reach it over SSH
  (`ssh -L 9443:127.0.0.1:9443 collector.example.com`).
- The collector never sends data anywhere: no webhooks, no exports, no
  metrics push. Data leaves only as operator-produced IOC export files that
  you copy off the box.
- TLS `[collector].tls_enabled` with real certificates in production; bearer
  token is `ingest_token`, ≥ 32 chars, generated with
  `openssl rand -hex 32`, stored with file mode 0600 next to the config.
  Rotate per region revoke by replacing `[nodes]` and restarting.

## Sensor config (`phptopwn.toml` on each sensor)

```toml
[fleet]
enabled = true
node_id = "eu-lab-1"                 # must appear in the collector's [nodes]
region = "eu-west"
collector_url = "https://collector-eu.example.net:9443"
collector_token = "<shared with that collector>"
buffer_dir = "fleet"
batch_max = 256                      # max events per POST
batch_max_bytes = 4194304            # ≤ 16 MiB
flush_interval_seconds = 3.0
timeout_seconds = 10.0
max_buffer_bytes = 268435456         # ≥ 4x batch_max_bytes; drop-oldest ring
```

## Collector config (`collect.toml`)

```toml
[collector]
host = "0.0.0.0"
port = 9443
tls_enabled = true
cert_file = "certs/collector.crt"
key_file = "certs/collector.key"
ingest_token = "<same token as the sensors>"
data_dir = "collector-data"          # dedicated volume; never "/" or "."
max_event_bytes = 2097152
max_batch_bytes = 33554432           # ≥ sensor batch_max_bytes + slop (see SCHEMA.md)
max_batch_events = 8192
dedupe_days = 3
ingest_rate_per_minute = 600         # per remote IP; 0 disables
dashboard = true                     # loopback-viewed HTML

[nodes]
eu-lab-1 = "eu-west"
as-lab-1 = "south-asia"
as-lab-2 = "south-asia"
me-lab-1 = "gulf"
```

`[nodes]` is the authoritative node→region map: an ingest from an unlisted
`node_id` is rejected with 403, and region attribution cannot be spoofed by
headers.

## Run

```bash
# sensor side (after normal sensor deployment)
phptopwn serve                        # starts fleet forwarder thread automatically

# collector side
phptopwn-collect serve --config collect.toml            # uvicorn, TLS if enabled
phptopwn-collect ioc --day 20261106 --config collect.toml --out exports/
phptopwn-collect ioc --day 20261106 --out exports/ --force   # overwrite existing
```

State and health:

- Sensor: `/healthz` on the internal metrics port shows
  `fleet_events_shipped`, `fleet_bytes_shipped`, `fleet_event_skips`.
- Collector: `GET /healthz` returns ingest counters and the last raw days.
- Backlog/drop semantics: an offline collector leaves data in
  `fleet/outbox.jsonl`; above `max_buffer_bytes` the oldest backlog is skipped
  (counted, logged, offset advanced past whole lines). After a clean full
  shipment the outbox is truncated only when it exceeded 64 MiB.

## Pre-deployment gates (must pass before any live sensor ships to collectors)

1. Self-test storm: run the lab-rate selftest on each new sensor and confirm
   the forwarder keeps up with `batch_max` under burst, with no `skips`.
2. Oversize body: push a request over `max_event_bytes` per line and confirm
   the collector reports `line_too_large` once for it — and that the rest of
   that batch was accepted.
3. Failover: stop the collector, generate events, start the collector —
   confirm buffered shipment resumes oldest-first with no net loss.
4. External fingerprint pass: probe your own sensors from a separate
   operator box (Shodan-style banner and behavior sweep, self-owned nodes
   only) and confirm the decoy surface looks as intended.
5. Content-type/auth sweep: wrong token → 401, wrong node → 403, wrong
   content type → 415, oversized batch → 413, all visible in collector logs.

## Governance (research freeze)

Once a collection window starts (methodology.md is frozen):

- No code changes on sensors or collectors except scoring-threshold tuning;
- Every threshold change gets a dated entry in `docs/threshold-log.md`.
- All raw events are retained; nothing deletes under you.
- No data leaves a collector other than your own `phptopwn-collect ioc`
  exports you chose to copy.

Classification thresholds for behavioral scoring are placeholders until the
ground-truth lab run exists; do not treat any dashboard number as a finding.
