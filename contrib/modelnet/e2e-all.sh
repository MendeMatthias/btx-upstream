#!/usr/bin/env bash
# Fail-fast in-tree 0.34.7 model-hosting suite. First failing command exits.
# Does not start granite, does not touch production btxd, does not cmake.
#
# Usage (coordinator, after build-gcc13):
#   contrib/modelnet/e2e-all.sh
export LC_ALL=C
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
BIN="${BIN_DIR:-$ROOT/build-gcc13/bin}"
export MODELD="${MODELD:-$BIN/btx-modeld}"

die() { printf 'E2E_ALL FAIL: %s\n' "$*" >&2; exit 1; }
step() { printf '\n== %s ==\n' "$*"; }

[[ -x "$BIN/btx-modeld" ]] || die "missing $BIN/btx-modeld"
[[ -x "$BIN/test_btx" ]] || die "missing $BIN/test_btx"

step "1/12 modelnet unit tests"
"$BIN/test_btx" --run_test=modelnet_* || die "test_btx modelnet_*"

step "2/12 reference codecs"
( cd "$ROOT/contrib/modelnet/reference" && python3 -m unittest -v test_v11 ) || die "reference unittest"

step "3/12 DOC examples"
BIN_DIR="$BIN" "$ROOT/contrib/modelnet/validate-doc-examples.sh" || die "validate-doc-examples"

step "4/12 two-helper loopback (no seedmodel)"
MODELD="$MODELD" "$ROOT/contrib/modelnet/e2e-two-helper-pq1.sh" || die "e2e-two-helper-pq1"

step "5/12 local helper"
MODELD="$MODELD" "$ROOT/contrib/modelnet/e2e-local-helper.sh" || die "e2e-local-helper"

step "6/12 resolve 8/4"
MODELD="$MODELD" "$ROOT/contrib/modelnet/e2e-resolve-8-4.sh" || die "e2e-resolve-8-4"

step "7/12 NAT congested + resume"
MODELD="$MODELD" "$ROOT/contrib/modelnet/e2e-nat-congested.sh" || die "e2e-nat-congested"

step "8/12 DISC-04/05 introducer death failover"
MODELD="$MODELD" "$ROOT/contrib/modelnet/e2e-disc-failure.sh" || die "e2e-disc-failure"

step "9/12 §12.3 32 MiB bench"
MODELD="$MODELD" "$ROOT/contrib/modelnet/e2e-bench-12-3.sh" || die "e2e-bench-12-3"

step "10/12 OpenSSL 3.5.8 second-process"
MODELD="$MODELD" "$ROOT/contrib/modelnet/e2e-openssl-358.sh" || die "e2e-openssl-358"

step "11/12 TLS max_send_fragment=512"
MODELD="$MODELD" "$ROOT/contrib/modelnet/e2e-tls-fragment.sh" || die "e2e-tls-fragment"

step "12/12 GUI URI source + OS handler"
"$ROOT/contrib/modelnet/e2e-gui-uri.sh" || die "e2e-gui-uri"

if [[ -x /usr/bin/google-chrome ]]; then
  step "optional web bridge"
  "$ROOT/contrib/modelnet/e2e-bridge-optional.sh" || die "e2e-bridge-optional"
else
  echo "skip e2e-bridge-optional (no google-chrome)"
fi
step "bridge matrix BRIDGE-01..12"
"$ROOT/contrib/modelnet/e2e-bridge-matrix.sh" || die "e2e-bridge-matrix"
step "os handler"
"$ROOT/contrib/modelnet/e2e-os-handler.sh" || die "e2e-os-handler"
step "webpki tls"
"$ROOT/contrib/modelnet/e2e-webpki-tls.sh" || die "e2e-webpki-tls"

echo
echo "E2E_ALL PASS (local sequential). Prefer concurrent:"
echo "  contrib/modelnet/e2e-parallel-a.sh && contrib/modelnet/e2e-parallel-b.sh"
echo "Two-host: contrib/modelnet/e2e-regtest-two-host.sh"
echo "Cross-host inspect: contrib/modelnet/e2e-cross-host-inspect.sh"
echo "CUDA on a dedicated workstation: CUDA_HOST=... contrib/modelnet/cuda-isolated-e2e.sh"
exit 0
