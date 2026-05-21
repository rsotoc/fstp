#!/usr/bin/env bash
# Generate local dev TLS material for fstp-agent (gitignored under certs/).
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
CERT_DIR="${ROOT}/certs"
mkdir -p "$CERT_DIR"

if [[ -f "${CERT_DIR}/server.crt" && -f "${CERT_DIR}/server.key" ]]; then
  echo "Certs already exist: ${CERT_DIR}/server.{crt,key}"
  exit 0
fi

echo "Generating self-signed dev cert in ${CERT_DIR} ..."
openssl req -x509 -newkey rsa:2048 -days 825 -nodes \
  -keyout "${CERT_DIR}/server.key" \
  -out "${CERT_DIR}/server.crt" \
  -subj "/CN=localhost" \
  2>/dev/null || openssl req -x509 -newkey rsa:2048 -days 825 -nodes \
  -keyout "${CERT_DIR}/server.key" \
  -out "${CERT_DIR}/server.crt" \
  -subj "/CN=localhost"

chmod 600 "${CERT_DIR}/server.key"
echo "OK — ${CERT_DIR}/server.crt and server.key"
echo "Run: cd fstp && cargo run -p fstp-agent"
