#!/usr/bin/env bash
# Optional D09 public WebPKI operator kit.
# Generates a CSR + nginx/caddy snippet and re-proves the local-CA path.
# A real public certificate still needs an operator hostname and a CA.
# Fail-fast. Packaged CSV stays NOT_RUN. Native btx-modeld stays PQ1-only.
export LC_ALL=C
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
SCRATCH="${PUBLIC_WEBKI_OUT:-$ROOT/e2e-scratch/public-webpki-kit}"
OPENSSL_BIN="${OPENSSL_BIN:-openssl}"
HOST="${PUBLIC_BRIDGE_HOST:-models.example.test}"

die() { echo "PUBLIC_WEBPKI_KIT FAIL: $*" >&2; exit 1; }

rm -rf "$SCRATCH"
mkdir -p "$SCRATCH/local-ca" "$SCRATCH/public-csr"

echo "== local CA path (already the in-tree proof) =="
"$OPENSSL_BIN" req -x509 -newkey rsa:2048 -keyout "$SCRATCH/local-ca/key.pem" \
  -out "$SCRATCH/local-ca/ca.pem" -days 1 -nodes -subj '/CN=btx-bridge-local-ca' \
  >/dev/null 2>&1 || die "local CA"
"$OPENSSL_BIN" x509 -in "$SCRATCH/local-ca/ca.pem" -noout -subject | grep -q btx-bridge-local-ca \
  || die "ca subject"
echo "D09-LOCAL-CA PASS $SCRATCH/local-ca/ca.pem"

echo "== public CSR (operator submits this to a WebPKI CA) =="
"$OPENSSL_BIN" req -new -newkey rsa:2048 -nodes \
  -keyout "$SCRATCH/public-csr/key.pem" \
  -out "$SCRATCH/public-csr/request.csr" \
  -subj "/CN=${HOST}" \
  >/dev/null 2>&1 || die "csr"
[[ -s "$SCRATCH/public-csr/request.csr" ]] || die "empty csr"
echo "PUBLIC_CSR PASS $SCRATCH/public-csr/request.csr CN=$HOST"

LEFT="$(python3 - <<'PY'
s='pqwy06q0q7wwzy70aeq45sxnlvq3mr067yt4jzphzvnfn2c4zc24zxz665zdprf0nwgskvqq9cq365u9n8l25'
print(s[:42])
PY
)"
RIGHT="$(python3 - <<'PY'
s='pqwy06q0q7wwzy70aeq45sxnlvq3mr067yt4jzphzvnfn2c4zc24zxz665zdprf0nwgskvqq9cq365u9n8l25'
print(s[42:])
PY
)"
cat >"$SCRATCH/dns-42-43.txt" <<EOF
D09 DNS 42/43 split (example token, not a hosted model):
  ${LEFT}.${RIGHT}.split.example
Map both labels to the bridge A/AAAA. Native PQ1 does not use this hostname.
EOF

cat >"$SCRATCH/nginx.example.conf" <<EOF
# Public HTTPS edge in FRONT of modelbridge.py. Not native PQ.
# Native btx-modeld must stay ML-KEM-768 / ML-DSA-44.
server {
  listen 443 ssl;
  server_name ${HOST};
  ssl_certificate     /etc/ssl/certs/${HOST}.pem;
  ssl_certificate_key /etc/ssl/private/${HOST}.key;
  add_header Content-Security-Policy "default-src 'none'; style-src 'unsafe-inline'" always;
  add_header X-Content-Type-Options nosniff always;
  location / {
    proxy_pass http://127.0.0.1:8088;
  }
}
EOF

echo "PUBLIC_WEBPKI_KIT PASS"
echo "Operator still must: publish DNS 42/43, obtain a WebPKI cert for $HOST,"
echo "and run modelbridge.py behind this edge. Native helper remains PQ1."
exit 0
