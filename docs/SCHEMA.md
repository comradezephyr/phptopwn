# Event schema and collector envelope

This document is the contract between the sensor's fleet forwarder and the
regional collector. Both sides validate against it; changes are versioned via
the `schema` string, never by silently reinterpreting fields.

## Sensor event record (`phptopwn.event/1.0`)

One JSON object per line (`logs/exploits.json`, and the fleet outbox when
`[fleet].enabled`). Produced by `phptopwn.storage.build_record`.

```jsonc
{
  "schema": "phptopwn.event/1.0",     // fixed string; version gate
  "event": "http_request",           // record type
  "request_id": "a1b2c3...",         // unique per request (uuid4 hex)
  "timestamp": "2026-11-06T10:00:00.123Z",
  "tls": false,
  "sensor": {
    "name": "intranet.acme.local",   // decoy surface identity
    "version": "1.1.0.dev0",
    "server_token": "Apache/2.4.52 (Ubuntu)",
    "powered_by": "PHP/8.1.2"
  },
  "client": {
    "ip": "203.0.113.7",               // effective source IP (see below)
    "port": 51344,                     // raw TCP peer port
    "peer_ip": "172.18.0.9",           // raw TCP peer address (always present)
    "peer_port": 51344
  },
  "request": {
    "method": "POST", "scheme": "http", "host": "...", "path": "/upload.php",
    "raw_path": "...", "query": "...", "http_version": "1.1",
    "headers": [["name", "value"], ...],   // as received, order preserved
    "header_count": 12, "header_bytes": 480, "duplicate_headers": 0,
    "content_type": "multipart/form-data; boundary=...",
    "declared_content_length": 8123, "transfer_encoding": ""
  },
  "body": {
    "bytes": 8123, "stored_bytes": 8123,
    "sha256": "<hex64>",             // set only when bytes > 0
    "truncated": false,              // capture cap hit
    "incomplete": false, "disconnected": false, "timed_out": false,
    "chunk_count": 1,
    "chunk_gaps_seconds": [...], "max_chunk_gap_seconds": 0.0123,
    "first_byte_seconds": 0.004, "total_seconds": 0.881,
    "preview": "...",                // first probe_bytes, lossy text
    "saved_as": null                 // quarantine file name when stored
  },
  "multipart": null,                 // part structure when content_type is multipart
  "form": {}, "query": {},
  "analysis": { "is_exploit": true, "severity": "high", "signals": [...] },
  "artifacts": [                      // quarantined payloads
    { "kind": "uploaded_file", "sha256": "<hex64>", "bytes": 999, "file": "<sha256>.bin", ... }
  ],
  "response": { "status": 200, "headers": {} },
  "error": null
}
```

Only identity fields are contractually validated at the collector:
`schema`, `event`, `request_id` (1–128 chars of `[A-Za-z0-9._:-]`),
`timestamp` (RFC 3339), `client.ip`, `request.method`, `request.path`.
`client.peer_ip` is validated when present (string, 1–64 chars).
Everything else carries through verbatim.

## Client identity behind a tunnel

When the sensor is reached only through a Cloudflare tunnel, the raw TCP peer
is the `cloudflared` connector on the laptop — every client would otherwise
share one source name. Sensor configuration (`[sensor] client_ip_header`,
set to `CF-Connecting-IP` in the laptop compose stack) promotes that header's
first value to the effective `client.ip`, falling back to the raw peer when
the header is absent. The raw TCP peer is always kept untouched in
`client.peer_ip` / `client.peer_port`, so records preserve both identities:

- `client.ip` — the real attack source as seen by the Cloudflare edge.
- `client.peer_ip` — the tunnel connector (or, without `client_ip_header`,
  the direct peer).

Rate limiting and per-IP concurrency caps key on the effective `client.ip`,
which is correct because `CF-Connecting-IP` is written by the Cloudflare edge
and cannot be spoofed by a caller passing through it. Only set
`client_ip_header` when *all* traffic reaches the sensor through the tunnel —
a direct attacker able to reach the listener could otherwise forge the header
and rotate their apparent identity.

## Collector enrichment

Before storing, the collector adds exactly one key:

```jsonc
"collector": {
  "node": "eu-lab-1",                // [nodes] key the batch arrived under
  "region": "eu-west",               // resolved from the collector's own [nodes] table
  "received_at": "2026-11-06T10:00:01.456Z"
}
```

The `X-Phptopwn-Region` header sent by the sensor is logged for diagnostics
only — region attribution on the collector is authoritative from `[nodes]`, so
a misconfigured sensor cannot falsify its region.

## Raw store layout

```
<collector.data_dir>/
  raw/<YYYYMMDD>.jsonl   one JSON event per line, append-only, never pruned
  ids/<YYYYMMDD>.ids     request_id side-index, one per line, for dedupe
```

Day partitioning uses the event's own `timestamp` (UTC), not arrival time.
Raw files are not rewritten by the collector; retention is "keep for
archaeology". Exports are operator-driven only.

## Ingest wire format

`POST {collector_url}/v1/events`

- Body: `application/x-ndjson`, up to `[collector].max_batch_events` lines and
  `max_batch_bytes` bytes total. Separately, `max_event_bytes` caps each line.
- Headers: `Authorization: Bearer <ingest_token>` (constant-time compare),
  `X-Phptopwn-Node: <node_id>`, optional `X-Phptopwn-Region` (logging only).
- Response `200` always shapes the batch report; the sensor advances its
  offset based on it and never retries a batch that got a 200:

```jsonc
{ "accepted": 41, "duplicates": 2, "rejected": {"schema_mismatch": 1}, "total": 44 }
```

- Rejection reason codes: `line_too_large`, `blank`, `invalid_json`,
  `schema_mismatch`, `invalid_shape:<field>` (`event`, `request_id`,
  `timestamp`, `client`, `client.ip`, `request`, `request.method`,
  `request.path`).
- Non-200 responses exist for hard failures the sensor should retry: `401`
  (bad token), `403` (unknown node), `413` (batch above server caps),
  `415` (wrong content type), `429` (ingest rate limit).
  Deployment rule: keep the collector's caps at or above the sensor's
  (`max_batch_bytes` ≥ sensor `[fleet].batch_max_bytes` + one line;
  `max_batch_events` ≥ sensor `[fleet].batch_max`) so legitimate batches are
  never hard-rejected.

## Dedupe

`request_id` is deduped over a bounded window (`dedupe_days`, default 3),
backed by `ids/` files for today and the previous `dedupe_days - 1` days.
A crash between "batch shipped" and "offset advanced" re-sends at most one
batch per event; those re-sends are dropped here (counted in `duplicates`).
Dedupe is not a guarantee across window boundaries and is not a substitute
for the sensor's own state file.
