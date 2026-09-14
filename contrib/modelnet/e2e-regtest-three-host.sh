#!/usr/bin/env bash
# Isolated regtest btxd + btx-modeld on three hosts. Fail-fast.
# Third isolated client: same tiny imported URI via a tunnel, demand-seed.
# Never production btxd. Never granite seeder port. Never SIGKILL.
#
#   SEEDER_HOST=... FETCHER_HOST=... THIRD_HOST=... \
#   SEEDER_PROD_PIDS=... FETCHER_PROD_PIDS=... THIRD_PROD_PIDS=... \
#   SEEDER_BTXD=... SEEDER_MODELD=... SEEDER_DIR=... \
#   FETCHER_BTXD=... FETCHER_MODELD=... FETCHER_DIR=... \
#   THIRD_BTXD=... THIRD_MODELD=... THIRD_DIR=... \
#     contrib/modelnet/e2e-regtest-three-host.sh
#
# THIRD_PROD_PIDS is optional (checked only if set). Binary/dir overrides match
# e2e-regtest-two-host.sh plus THIRD_*.
set -euo pipefail
export LC_ALL=C

SEEDER="${SEEDER_HOST:?set SEEDER_HOST to SSH alias of the seeder}"
FETCHER="${FETCHER_HOST:?set FETCHER_HOST to SSH alias of the fetcher}"
THIRD="${THIRD_HOST:?set THIRD_HOST to SSH alias of the third isolated host}"
MODELD_PORT="${REGTEST_MODELD_PORT:-29449}"
SEEDER_DIR="${SEEDER_DIR:-/opt/btx-0347-rc/regtest-e2e}"
FETCHER_DIR="${FETCHER_DIR:-\$HOME/.local/opt/btx-0.34.7-rc-regtest}"
THIRD_DIR="${THIRD_DIR:-\$HOME/.local/opt/btx-0.34.7-rc-regtest}"
SEEDER_BTXD="${SEEDER_BTXD:-/opt/btx-node/bin/btxd}"
SEEDER_CLI="${SEEDER_CLI:-${SEEDER_BTXD%/*}/btx-cli}"
SEEDER_MODELD="${SEEDER_MODELD:-}"
FETCHER_BTXD="${FETCHER_BTXD:-\$HOME/.local/opt/btx-0.34.7-b094c6ba420f/bin/btxd}"
FETCHER_CLI="${FETCHER_CLI:-${FETCHER_BTXD%/*}/btx-cli}"
FETCHER_MODELD="${FETCHER_MODELD:-\$HOME/.local/opt/btx-0.34.7-rc-modeld/bin/btx-modeld}"
THIRD_BTXD="${THIRD_BTXD:-/Users/admin/Documents/btx-0341-metal/build-metal/bin/btxd}"
THIRD_CLI="${THIRD_CLI:-${THIRD_BTXD%/*}/btx-cli}"
THIRD_MODELD="${THIRD_MODELD:-/Users/admin/Documents/btx-0341-metal/build-metal/bin/btx-modeld}"
PROD_SEEDER="${SEEDER_PROD_PIDS:?set SEEDER_PROD_PIDS}"
PROD_FETCHER="${FETCHER_PROD_PIDS:?set FETCHER_PROD_PIDS}"
PROD_THIRD="${THIRD_PROD_PIDS:-}"

die() { echo "E2E_REGTEST_THREE FAIL: $*" >&2; cleanup || true; exit 1; }
TUNNEL_S=""
TUNNEL_F=""
TUNNEL_T=""
cleanup() {
  [[ -n "${TUNNEL_S}" ]] && kill -TERM "$TUNNEL_S" 2>/dev/null || true
  [[ -n "${TUNNEL_F}" ]] && kill -TERM "$TUNNEL_F" 2>/dev/null || true
  [[ -n "${TUNNEL_T}" ]] && kill -TERM "$TUNNEL_T" 2>/dev/null || true
  ssh -o BatchMode=yes "$SEEDER" "for f in ${SEEDER_DIR}/btxd.pid ${SEEDER_DIR}/modeld.pid; do [[ -f \$f ]] && kill -TERM \$(cat \$f) 2>/dev/null || true; done" || true
  ssh -o BatchMode=yes "$FETCHER" "for f in ${FETCHER_DIR}/btxd.pid ${FETCHER_DIR}/modeld.pid; do [[ -f \$f ]] && kill -TERM \$(cat \$f) 2>/dev/null || true; done" || true
  ssh -o BatchMode=yes "$THIRD" "for f in ${THIRD_DIR}/btxd.pid ${THIRD_DIR}/modeld.pid; do [[ -f \$f ]] && kill -TERM \$(cat \$f) 2>/dev/null || true; done" || true
}
trap 'rc=$?; cleanup; exit $rc' EXIT

if [[ "${MODELD_PORT}" == "29448" ]]; then
  die "REFUSE granite seeder port 29448; set REGTEST_MODELD_PORT (default 29449)"
fi
if [[ "$THIRD" == "$SEEDER" || "$THIRD" == "$FETCHER" ]]; then
  die "THIRD_HOST must be a distinct SSH alias (not SEEDER_HOST or FETCHER_HOST)"
fi

prod_up() {
  local host="$1" pids="$2"
  local have
  have="$(ssh -o BatchMode=yes "$host" "ps -p ${pids} -o pid=" || true)"
  local p
  IFS=',' read -r -a want <<<"$pids"
  for p in "${want[@]}"; do
    echo "$have" | grep -q "$p" || die "$host production pid $p is gone"
  done
}

echo "== production PIDs must remain =="
prod_up "$SEEDER" "$PROD_SEEDER"
prod_up "$FETCHER" "$PROD_FETCHER"
if [[ -n "$PROD_THIRD" ]]; then
  prod_up "$THIRD" "$PROD_THIRD"
fi

start_seeder() {
  ssh -o BatchMode=yes "$SEEDER" "bash -s" <<EOF
set -euo pipefail
DIR="${SEEDER_DIR}"
BTXD="${SEEDER_BTXD}"
MODELD="${SEEDER_MODELD}"
PORT="${MODELD_PORT}"
rm -rf "\$DIR"
mkdir -p "\$DIR/btxd" "\$DIR/modeld" "\$DIR/src"
python3 -c "import struct; from pathlib import Path; Path('\$DIR/src/model.safetensors').write_bytes(struct.pack('<Q', 2)+b'{}')"
nohup "\$BTXD" -regtest -datadir="\$DIR/btxd" -server \\
  -listen=0 -port=18444 -rpcport=18443 -rpcuser=regtest -rpcpassword=regtest \\
  -fallbackfee=0.0002 -disablewallet \\
  -regtestmatmulbindingheight=2147483647 \\
  -regtestmatmulproductdigestheight=2147483647 \\
  -regtestmatmulv4height=2147483647 \\
  -regtestmatmulrequireproductpayload=0 \\
  >"\$DIR/btxd.log" 2>&1 &
echo \$! > "\$DIR/btxd.pid"
if [[ -z "\$MODELD" ]]; then
  MODELD=/opt/btx-0347-rc/bin/btx-modeld
  export LD_LIBRARY_PATH="/opt/btx-0347-rc/lib\${LD_LIBRARY_PATH:+:\$LD_LIBRARY_PATH}"
  if [[ -x /opt/btx-0347-rc/bin/run-modeld.sh ]]; then MODELD=/opt/btx-0347-rc/bin/run-modeld.sh; fi
else
  prefix=\$(cd "\$(dirname "\$MODELD")/.." && pwd)
  if [[ -d "\$prefix/lib" ]]; then
    export LD_LIBRARY_PATH="\$prefix/lib\${LD_LIBRARY_PATH:+:\$LD_LIBRARY_PATH}"
  fi
fi
nohup "\$MODELD" \\
  -modeldir="\$DIR/modeld" \\
  -modelstorage=80MiB \\
  -modelbind=127.0.0.1:\$PORT \\
  -modelhost \\
  -modelrpcsocket="\$DIR/modeld/modeld.sock" \\
  >"\$DIR/modeld.log" 2>&1 &
echo \$! > "\$DIR/modeld.pid"
EOF
}

start_client() {
  local host="$1" dir="$2" btxd="$3" modeld="$4" p2p="$5" rpcport="$6"
  ssh -o BatchMode=yes "$host" "bash -s" <<EOF
set -euo pipefail
DIR="${dir}"
BTXD="${btxd}"
MODELD="${modeld}"
rm -rf "\$DIR"
mkdir -p "\$DIR/btxd" "\$DIR/modeld"
nohup "\$BTXD" -regtest -datadir="\$DIR/btxd" -server \\
  -listen=0 -port=${p2p} -rpcport=${rpcport} -rpcuser=regtest -rpcpassword=regtest \\
  -fallbackfee=0.0002 -disablewallet \\
  -regtestmatmulbindingheight=2147483647 \\
  -regtestmatmulproductdigestheight=2147483647 \\
  -regtestmatmulv4height=2147483647 \\
  -regtestmatmulrequireproductpayload=0 \\
  >"\$DIR/btxd.log" 2>&1 &
echo \$! > "\$DIR/btxd.pid"
prefix=\$(cd "\$(dirname "\$MODELD")/.." && pwd)
if [[ -d "\$prefix/lib" ]]; then
  export LD_LIBRARY_PATH="\$prefix/lib\${LD_LIBRARY_PATH:+:\$LD_LIBRARY_PATH}"
fi
# client: no -modelseed=auto (prove default demand-seed). No granite port.
nohup "\$MODELD" \\
  -modeldir="\$DIR/modeld" \\
  -modelstorage=80MiB \\
  -modelrpcsocket="\$DIR/modeld/modeld.sock" \\
  >"\$DIR/modeld.log" 2>&1 &
echo \$! > "\$DIR/modeld.pid"
EOF
}

echo "== start isolated regtest btxd + modeld =="
start_seeder
start_client "$FETCHER" "$FETCHER_DIR" "$FETCHER_BTXD" "$FETCHER_MODELD" 18454 18453
start_client "$THIRD" "$THIRD_DIR" "$THIRD_BTXD" "$THIRD_MODELD" 18464 18463

wait_sock() {
  local host="$1" path="$2" pidfile="$3" log="$4"
  local i out
  for i in $(seq 1 40); do
    out="$(ssh -o BatchMode=yes -o ConnectTimeout=8 "$host" \
      "if [ -f $pidfile ] && ! kill -0 \$(cat $pidfile) 2>/dev/null; then echo DEAD; tail -n 40 $log; elif [ -S $path ]; then echo READY; fi")" \
      || die "$host ssh failed waiting for $path"
    if printf '%s\n' "$out" | grep -q '^READY$'; then return 0; fi
    if printf '%s\n' "$out" | grep -q '^DEAD$'; then
      printf '%s\n' "$out" >&2
      die "$host helper died before socket: $path"
    fi
    sleep 0.15
  done
  ssh -o BatchMode=yes -o ConnectTimeout=8 "$host" "tail -n 40 $log" >&2 || true
  die "$host socket not ready: $path"
}

wait_rpc() {
  local host="$1" cli="$2" datadir="$3" rpcport="$4" pidfile="$5" log="$6"
  local i out
  for i in $(seq 1 25); do
    out="$(ssh -o BatchMode=yes -o ConnectTimeout=8 "$host" \
      "if [ -f $pidfile ] && ! kill -0 \$(cat $pidfile) 2>/dev/null; then echo DEAD; tail -n 40 $log; exit 2; fi
       $cli -regtest -datadir=$datadir -rpcport=$rpcport -rpcuser=regtest -rpcpassword=regtest getblockchaininfo")" \
      && { printf '%s\n' "$out"; return 0; } || true
    if printf '%s\n' "$out" | grep -q '^DEAD$'; then
      printf '%s\n' "$out" >&2
      die "$host btxd died before RPC"
    fi
    sleep 0.2
  done
  ssh -o BatchMode=yes -o ConnectTimeout=8 "$host" "tail -n 40 $log" >&2 || true
  die "$host btxd RPC :$rpcport not ready"
}

wait_sock "$SEEDER" "${SEEDER_DIR}/modeld/modeld.sock" "${SEEDER_DIR}/modeld.pid" "${SEEDER_DIR}/modeld.log"
wait_sock "$FETCHER" "${FETCHER_DIR}/modeld/modeld.sock" "${FETCHER_DIR}/modeld.pid" "${FETCHER_DIR}/modeld.log"
wait_sock "$THIRD" "${THIRD_DIR}/modeld/modeld.sock" "${THIRD_DIR}/modeld.pid" "${THIRD_DIR}/modeld.log"

echo "== isolated monetary nodes =="
SEED_CHAIN="$(wait_rpc "$SEEDER" "${SEEDER_CLI}" "${SEEDER_DIR}/btxd" 18443 "${SEEDER_DIR}/btxd.pid" "${SEEDER_DIR}/btxd.log")"
echo "$SEED_CHAIN" | python3 -c 'import json,sys; i=json.load(sys.stdin); assert i.get("chain")=="regtest", i; print("seeder", i["chain"], "blocks", i.get("blocks"))' || die "seeder not regtest: $SEED_CHAIN"
FETCH_CHAIN="$(wait_rpc "$FETCHER" "${FETCHER_CLI}" "${FETCHER_DIR}/btxd" 18453 "${FETCHER_DIR}/btxd.pid" "${FETCHER_DIR}/btxd.log")"
echo "$FETCH_CHAIN" | python3 -c 'import json,sys; i=json.load(sys.stdin); assert i.get("chain")=="regtest", i; print("fetcher", i["chain"], "blocks", i.get("blocks"))' || die "fetcher not regtest: $FETCH_CHAIN"
THIRD_CHAIN="$(wait_rpc "$THIRD" "${THIRD_CLI}" "${THIRD_DIR}/btxd" 18463 "${THIRD_DIR}/btxd.pid" "${THIRD_DIR}/btxd.log")"
echo "$THIRD_CHAIN" | python3 -c 'import json,sys; i=json.load(sys.stdin); assert i.get("chain")=="regtest", i; print("third", i["chain"], "blocks", i.get("blocks"))' || die "third not regtest: $THIRD_CHAIN"

echo "== SSH tunnels seeder:${MODELD_PORT} -> fetcher/third 127.0.0.1:${MODELD_PORT} =="
ssh -o BatchMode=yes -N -L "127.0.0.1:${MODELD_PORT}:127.0.0.1:${MODELD_PORT}" "$SEEDER" &
TUNNEL_S=$!
ssh -o BatchMode=yes -N -R "127.0.0.1:${MODELD_PORT}:127.0.0.1:${MODELD_PORT}" "$FETCHER" &
TUNNEL_F=$!
ssh -o BatchMode=yes -N -R "127.0.0.1:${MODELD_PORT}:127.0.0.1:${MODELD_PORT}" "$THIRD" &
TUNNEL_T=$!
sleep 0.5
kill -0 "$TUNNEL_S" 2>/dev/null || die "seeder tunnel died"
kill -0 "$TUNNEL_F" 2>/dev/null || die "fetcher tunnel died"
kill -0 "$TUNNEL_T" 2>/dev/null || die "third tunnel died"

echo "== import on seeder (demand-seed, no seedmodel) =="
URI="$(ssh -o BatchMode=yes "$SEEDER" "DIR=${SEEDER_DIR} python3 -s" <<'PY'
import json, os, socket, sys
from pathlib import Path
sock = Path(os.environ["DIR"]) / "modeld" / "modeld.sock"

def rpc(method, params):
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.settimeout(10)
    s.connect(str(sock))
    s.sendall((json.dumps({"jsonrpc": "1.0", "id": 1, "method": method, "params": params}) + "\n").encode())
    s.shutdown(socket.SHUT_WR)
    data = b""
    while True:
        c = s.recv(1 << 20)
        if not c:
            break
        data += c
        if b"\n" in data:
            break
    s.close()
    msg = json.loads(data.decode())
    if msg.get("error"):
        sys.exit(str(msg["error"]))
    return msg.get("result") or {}

prop = (rpc("getmodelnetworkinfo", []) or {}).get("propagation") or {}
if not prop.get("demand_propagation"):
    sys.exit("demand_propagation false: " + json.dumps(prop))
if prop.get("seed_upon_download_opt_in"):
    sys.exit("seed_upon_download still opt-in")
imp = rpc("importmodel", [str(Path(os.environ["DIR"]) / "src"), {"pin": True}])
if imp.get("seeded") is not True:
    sys.exit("import not demand-seeded: " + json.dumps(imp))
print(imp["uri"])
PY
)"
[[ "$URI" == btx://* ]] || die "import uri: $URI"
echo "uri $URI"

client_getmodel() {
  local host="$1" dir="$2" label="$3"
  ssh -o BatchMode=yes "$host" "DIR=${dir} URI='$URI' PORT=${MODELD_PORT} LABEL='$label' python3 -s" <<'PY'
import json, os, socket, sys, time
from pathlib import Path
sock = Path(os.environ["DIR"]) / "modeld" / "modeld.sock"
uri = os.environ["URI"]
port = os.environ["PORT"]
label = os.environ["LABEL"]

def rpc(method, params, timeout=15):
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.settimeout(timeout)
    s.connect(str(sock))
    s.sendall((json.dumps({"jsonrpc": "1.0", "id": 1, "method": method, "params": params}) + "\n").encode())
    s.shutdown(socket.SHUT_WR)
    data = b""
    while True:
        c = s.recv(1 << 20)
        if not c:
            break
        data += c
        if b"\n" in data:
            break
    s.close()
    msg = json.loads(data.decode())
    if msg.get("error"):
        sys.exit(str(msg["error"]))
    return msg.get("result") or {}

def pick_job(jobs, job_id):
    arr = jobs.get("jobs") or []
    for x in arr:
        if x.get("job_id") == job_id:
            return x
    running = [x for x in arr if x.get("status") == "running"]
    if running:
        return running[-1]
    return arr[-1] if arr else {}

prop = (rpc("getmodelnetworkinfo", []) or {}).get("propagation") or {}
if not prop.get("demand_propagation"):
    sys.exit("%s demand_propagation false: %s" % (label, json.dumps(prop)))
rpc("addmodelnode", ["127.0.0.1:%s" % port])
got = rpc("getmodel", [uri, "FREE_ONLY"])
print(label, "getmodel", json.dumps(got), flush=True)

def prove_seeded():
    listed = rpc("listmodels", [])
    m = (listed.get("models") or [{}])[0]
    if m.get("seeded") is not True:
        sys.exit("%s downloader not demand-seeded: %s" % (label, json.dumps(listed)))
    print("%s retrieve PASS" % label, json.dumps({"bytes": m.get("bytes"), "seeded": m.get("seeded")}))
    raise SystemExit(0)

if got.get("status") in ("retrieved", "local"):
    prove_seeded()
job_id = got.get("job_id")
if not job_id:
    sys.exit("%s no job: %s" % (label, json.dumps(got)))
t0 = time.time()
while time.time() - t0 < 15:
    j = pick_job(rpc("getmodeljob", [job_id]), job_id)
    if j:
        print(label, "job", j.get("job_id"), j.get("status"), j.get("error") or j.get("last_err"), flush=True)
        if j.get("status") == "failed":
            sys.exit("%s retrieve failed: %s" % (label, json.dumps(j)))
        if j.get("status") == "cancelled":
            sys.exit("%s retrieve not done: %s" % (label, json.dumps(j)))
        if j.get("status") == "done":
            prove_seeded()
    time.sleep(0.25)
sys.exit("%s retrieve timeout 15s" % label)
PY
}

echo "== getmodel on fetcher via tunnel (demand-seed) =="
client_getmodel "$FETCHER" "$FETCHER_DIR" "fetcher"
echo "== getmodel on third via tunnel (demand-seed) =="
client_getmodel "$THIRD" "$THIRD_DIR" "third"

echo "== production PIDs still up =="
prod_up "$SEEDER" "$PROD_SEEDER"
prod_up "$FETCHER" "$PROD_FETCHER"
if [[ -n "$PROD_THIRD" ]]; then
  prod_up "$THIRD" "$PROD_THIRD"
fi
echo "E2E_REGTEST_THREE PASS"
trap - EXIT
cleanup
exit 0
