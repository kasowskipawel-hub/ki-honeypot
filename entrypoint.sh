#!/bin/sh
# Generate self-signed TLS cert if not already present, then exec the command.
CERT="${CERT:-/data/cert.pem}"
KEY="${KEY:-/data/key.pem}"

mkdir -p "$(dirname "$CERT")" /data/samples /data/trap_logs

if [ ! -f "$CERT" ] || [ ! -f "$KEY" ]; then
    echo "[entrypoint] generating self-signed cert..."
    openssl req -x509 -newkey rsa:2048 -nodes \
        -subj "/CN=WIN-$(cat /proc/sys/kernel/random/uuid 2>/dev/null | head -c8 | tr '[:lower:]' '[:upper:]')/O=Microsoft Corporation/C=US" \
        -out "$CERT" -keyout "$KEY" -days 3650 2>/dev/null
    echo "[entrypoint] cert generated: $CERT"
fi

exec "$@"
