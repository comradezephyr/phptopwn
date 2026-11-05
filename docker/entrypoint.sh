#!/bin/sh
# Generate a throw-away self-signed certificate for the TLS listener, then hand
# control to the sensor. No attacker data ever reaches an interpreter here.
set -eu

CERT_FILE="${PHPTOPWN_CERT_FILE:-certs/honeypot.crt}"
KEY_FILE="${PHPTOPWN_KEY_FILE:-certs/honeypot.key}"
TLS_ENABLED="${PHPTOPWN_TLS:-false}"

case "${TLS_ENABLED}" in
    true|TRUE|1|yes|on)
        mkdir -p "$(dirname "${CERT_FILE}")" "$(dirname "${KEY_FILE}")"
        if [ ! -s "${CERT_FILE}" ] || [ ! -s "${KEY_FILE}" ]; then
            echo "[entrypoint] generating self-signed certificate for ${PHPTOPWN_SERVER_NAME:-intranet.acme.local}"
            openssl req -x509 -nodes -newkey rsa:2048 -days 365 \
                -keyout "${KEY_FILE}" \
                -out "${CERT_FILE}" \
                -subj "/C=US/ST=California/L=San Francisco/O=Acme Intranet/CN=${PHPTOPWN_SERVER_NAME:-intranet.acme.local}"
            chmod 0600 "${KEY_FILE}"
        fi
        ;;
esac

exec phptopwn
