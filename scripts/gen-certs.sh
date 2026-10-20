#!/usr/bin/env bash
# TLS hardening (v0.12): generate a self-signed CA + SAN server
# certificate for the NDR platform (gateway / direct uvicorn TLS).
#
# Usage:
#   ./scripts/gen-certs.sh [COMMON_NAME] [DAYS]
#     COMMON_NAME  DNS name in the cert CN/SAN (default: ndr.local)
#     DAYS         validity in days (default: 825)
#
# Output (created if missing): deploy/tls/
#   ca.crt / ca.key      local CA (keep ca.key OFF the servers)
#   server.crt           SAN server certificate
#   server.key           server private key (chmod 600)
#   dhparam.pem          2048-bit DH params (slow on first run)
#
# NOTE: self-signed certificates are for lab/PoC deployments. For
# production, replace server.crt/server.key with your CA-issued pair
# (e.g. from the internal PKI) and keep the same file names - the
# gateway profile mounts exactly these paths.
set -euo pipefail

# v0.13.0: idempotent - an existing server identity is NEVER silently
# overwritten (regenerating would change the cert every run and break
# browser trust + pinned fingerprints). Force only with FORCE_TLS_GEN=1.
if [ "${FORCE_TLS_GEN:-0}" != "1" ] && [ -f deploy/tls/server.crt ] \
   && [ -f deploy/tls/server.key ]; then
  echo "[gen-certs] deploy/tls/server.crt already exists - keeping it"
  echo "[gen-certs] set FORCE_TLS_GEN=1 to regenerate deliberately"
  exit 0
fi

CN="${1:-ndr.local}"
DAYS="${2:-825}"
DIR="$(cd "$(dirname "$0")/.." && pwd)/deploy/tls"
mkdir -p "$DIR"
cd "$DIR"

echo "[1/4] Local CA"
if [ ! -f ca.crt ]; then
  openssl req -x509 -newkey rsa:4096 -sha256 -days "$DAYS" -nodes \
    -keyout ca.key -out ca.crt -subj "/CN=NDR Platform Local CA/O=NDR" \
    -addext "basicConstraints=critical,CA:TRUE" \
    -addext "keyUsage=critical,keyCertSign,cRLSign"
else
  echo "      ca.crt exists - reuse"
fi

echo "[2/4] Server key + CSR (${CN})"
openssl req -newkey rsa:2048 -sha256 -nodes \
  -keyout server.key -out server.csr \
  -subj "/CN=${CN}/O=NDR Platform"

echo "[3/4] Sign server cert (SAN: ${CN}, ndr.local, localhost, API/UI hostnames)"
cat > server-ext.cnf <<EOF
subjectAltName=DNS:${CN},DNS:ndr.local,DNS:localhost,IP:127.0.0.1
keyUsage=critical,digitalSignature,keyEncipherment
extendedKeyUsage=serverAuth
basicConstraints=critical,CA:FALSE
subjectKeyIdentifier=hash
EOF
openssl x509 -req -in server.csr -CA ca.crt -CAkey ca.key -CAcreateserial \
  -out server.crt -days "$DAYS" -sha256 -extfile server-ext.cnf

echo "[4/4] DH params (this can take a moment)"
if [ ! -f dhparam.pem ]; then
  openssl dhparam -out dhparam.pem 2048
else
  echo "      dhparam.pem exists - reuse"
fi

chmod 600 server.key ca.key
rm -f server.csr server-ext.cnf
echo "Done. Files in ${DIR}:"
ls -la "$DIR" | grep -E "crt|key|pem"
echo
echo "Enable the TLS gateway profile:"
echo "  TLS_ENABLED=1 docker compose --profile tls up -d gateway"
echo "  (browsers need the CA imported, or accept the self-signed warning)"
