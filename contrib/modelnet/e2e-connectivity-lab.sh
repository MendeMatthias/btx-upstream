#!/usr/bin/env bash
# Isolated connectivity lab. Loopback always. Namespace NAT only with CAP_NET_ADMIN.
# No production btxd, no public IPs, no granite unless BTX_SHARD19=1.
export LC_ALL=C
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
BIN="${MODELD:-$ROOT/build-gcc13/bin/btx-modeld}"
SCRATCH="$ROOT/e2e-scratch/connectivity-lab"
mkdir -p "$SCRATCH"
LOG="$SCRATCH/lab.log"
: >"$LOG"

die() { printf 'e2e-connectivity-lab: %s\n' "$*" >&2; exit 1; }
note() { printf '%s\n' "$*" | tee -a "$LOG"; }

[[ -x "$BIN" ]] || die "missing $BIN"

rpc() {
  local sock="$1" method="$2" params="${3:-[]}"
  python3 - "$sock" "$method" "$params" <<'PY'
import json, socket, sys
sock, method, params = sys.argv[1], sys.argv[2], json.loads(sys.argv[3])
req = json.dumps({"jsonrpc":"1.0","id":1,"method":method,"params":params}) + "\n"
s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
s.connect(sock)
s.sendall(req.encode())
s.shutdown(socket.SHUT_WR)
print(s.recv(1 << 20).decode())
PY
}

# --- A. loopback PUBLIC stand-in (two helpers, direct PQ1 path exists) ---
DIR_A="$SCRATCH/a"
DIR_B="$SCRATCH/b"
rm -rf "$DIR_A" "$DIR_B"
mkdir -p "$DIR_A" "$DIR_B"
PORT="$(python3 - <<'PY'
import socket
s = socket.socket(); s.bind(("127.0.0.1", 0)); print(s.getsockname()[1]); s.close()
PY
)"
"$BIN" -modeldir="$DIR_A" -modelrpcsocket="$DIR_A/modeld.sock" -modelbind="127.0.0.1:$PORT" \
  -modelcache=10485760 >"$DIR_A/modeld.log" 2>&1 &
PID_A=$!
for i in $(seq 1 50); do
  [[ -S "$DIR_A/modeld.sock" ]] && break
  sleep 0.1
done
[[ -S "$DIR_A/modeld.sock" ]] || die "helper A socket missing"
INFO="$(rpc "$DIR_A/modeld.sock" getmodelnetworkinfo)"
echo "$INFO" | python3 -c 'import json,sys; o=json.load(sys.stdin); r=o.get("result",o);
assert "reachability_state" in r, r
assert r.get("classical_fallback") is False or r.get("classical_fallback") is None
print("A reachability_state", r.get("reachability_state"))'
kill -TERM "$PID_A" 2>/dev/null || true
wait "$PID_A" 2>/dev/null || true
note "A loopback helper: getmodelnetworkinfo exposes reachability_state (listen != PUBLIC)"

if ! ip netns list >/dev/null 2>&1; then
  note "SKIP B-H: ip netns not available"
  note "NOT_RUN namespace topologies (cone/restricted/symmetric/double-NAT)"
  exit 0
fi
if ! ip netns add btx-conn-probe 2>/dev/null; then
  note "SKIP B-H: CAP_NET_ADMIN missing (cannot create netns)"
  note "NOT_RUN namespace topologies"
  exit 0
fi
ip netns delete btx-conn-probe 2>/dev/null || true
note "netns available; full NAT matrix not auto-applied in this session (manual nft rules)."
note "NOT_RUN C-H until nft topologies are applied by an operator with CAP_NET_ADMIN."
exit 0
