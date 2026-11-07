#!/bin/sh
# Collector entrypoint for the laptop fleet compose stack: renders the
# collector config from the environment, then starts the ingest service.
# Config keys mirror docs/FLEET.md; data lives on the /data volume only.
set -eu

TOKEN="${FLEET_TOKEN:?FLEET_TOKEN is required}"
NODE="${NODE_ID:?NODE_ID is required}"
REGION="${REGION:?REGION is required}"
DATA_DIR="${COLLECTOR_DATA_DIR:-/data}"
CONFIG_PATH="${COLLECTOR_CONFIG_PATH:-/tmp/collect.toml}"

case "${NODE}" in
    *[!a-z0-9-]*) echo "collector: NODE_ID must be [a-z0-9-]" >&2; exit 2 ;;
esac
case "${REGION}" in
    *[!a-z0-9-]*) echo "collector: REGION must be [a-z0-9-]" >&2; exit 2 ;;
esac

mkdir -p "${DATA_DIR}/raw" "${DATA_DIR}/ids" "${DATA_DIR}/ioc-exports"

cat > "${CONFIG_PATH}" <<EOF
[collector]
host = "0.0.0.0"
port = 9443
tls_enabled = false
ingest_token = "${TOKEN}"
data_dir = "${DATA_DIR}"
dashboard = true
max_event_bytes = 2097152
max_batch_bytes = 33554432
max_batch_events = 8192
dedupe_days = 3
ingest_rate_per_minute = 600

[nodes]
${NODE} = "${REGION}"
EOF

exec phptopwn-collect serve --config "${CONFIG_PATH}" --host 0.0.0.0
