#!/bin/sh
set -e

CERT_DIR="/app/certs"
CERT_FILE="$CERT_DIR/ca.crt"
KEY_FILE="$CERT_DIR/ca.key"

if [ ! -f "$CERT_FILE" ] || [ ! -f "$KEY_FILE" ]; then
  echo "Generating self-signed CA certificate..."
  mkdir -p "$CERT_DIR"
  openssl req -x509 -newkey rsa:2048 -nodes \
    -keyout "$KEY_FILE" \
    -out "$CERT_FILE" \
    -days 3650 \
    -subj "/CN=OpenScanProxy CA/O=OpenScanProxy" 2>/dev/null
  echo "CA certificate generated at $CERT_FILE"
fi

exec ./openscanproxy "$@"
