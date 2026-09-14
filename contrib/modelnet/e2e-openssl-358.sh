#!/usr/bin/env bash
# Second-process OpenSSL 3.5.8 PQ1. Never swaps production btxd.real.
# PQ-19: hostile OPENSSL_CONF cannot weaken PQ1. Fail-fast.
export LC_ALL=C
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
PREFIX="${OPENSSL358_PREFIX:-$HOME/.local/opt/openssl-3.5.8}"
BIN="$ROOT/build-gcc13/bin"
SCRATCH="$ROOT/e2e-scratch/openssl358"
die() { echo "E2E_OPENSSL358 FAIL: $*" >&2; exit 1; }
[[ -x "$PREFIX/bin/openssl" ]] || die "missing $PREFIX"
[[ -x "$BIN/btx-modeld" ]] || die "missing btx-modeld"
rm -rf "$SCRATCH"; mkdir -p "$SCRATCH"
export LD_LIBRARY_PATH="$PREFIX/lib:${LD_LIBRARY_PATH:-}"
ver="$("$PREFIX/bin/openssl" version)"
echo "$ver" | grep -q '3.5.8' || die "openssl not 3.5.8: $ver"
echo "$ver" | grep -q 'Library: OpenSSL 3.5.8' || die "library not 3.5.8: $ver"

# PQ-19 hostile conf (X25519 + AES-128). Helper must still report MLKEM768.
cat >"$SCRATCH/hostile.cnf" <<'EOF'
openssl_conf = openssl_init
[openssl_init]
ssl_conf = ssl_sect
[ssl_sect]
system_default = sys
[sys]
MinProtocol = TLSv1.2
CipherString = DEFAULT@SECLEVEL=1
Groups = X25519
EOF
export OPENSSL_CONF="$SCRATCH/hostile.cnf"
export OPENSSL_MODULES="/nonexistent-pq19-modules"
export BTX_OPENSSL="$PREFIX/bin/openssl"

pick() { python3 -c 'import socket; s=socket.socket(); s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1); s.bind(("127.0.0.1",0)); print(s.getsockname()[1]); s.close()'; }
PORT="$(pick)"
mkdir -p "$SCRATCH/a/src" "$SCRATCH/b"
python3 -c 'import struct; from pathlib import Path; Path("'"$SCRATCH"'/a/src/model.safetensors").write_bytes(struct.pack("<Q",2)+b"{}")'
PA=""; PB=""
cleanup() { for p in "$PB" "$PA"; do [[ -n "$p" ]] && kill -TERM "$p" 2>/dev/null || true; done; }
trap cleanup EXIT
"$BIN/btx-modeld" -modeldir="$SCRATCH/a" -modelstorage=8MiB -modelbind="127.0.0.1:${PORT}" -modelhost -modelrpcsocket="$SCRATCH/a/modeld.sock" >"$SCRATCH/a.log" 2>&1 &
PA=$!
"$BIN/btx-modeld" -modeldir="$SCRATCH/b" -modelstorage=8MiB -modelrpcsocket="$SCRATCH/b/modeld.sock" >"$SCRATCH/b.log" 2>&1 &
PB=$!
python3 - "$SCRATCH" "$PORT" "$PA" "$PB" "$ROOT/contrib/modelnet" <<'PY'
import json, os, socket, sys
from pathlib import Path
root, port, pa, pb = Path(sys.argv[1]), sys.argv[2], int(sys.argv[3]), int(sys.argv[4])
sys.path.insert(0, sys.argv[5])
from failfast import wait_unix, poll_job

def rpc(sock, method, params, timeout=20):
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM); s.settimeout(timeout)
    s.connect(str(sock))
    s.sendall(json.dumps({"jsonrpc":"1.0","id":1,"method":method,"params":params}).encode()+b"\n")
    s.shutdown(socket.SHUT_WR)
    data=b""
    while True:
        c=s.recv(65536)
        if not c: break
        data+=c
        if b"\n" in data: break
    s.close()
    m=json.loads(data.decode())
    if m.get("error"): raise SystemExit("%s: %s"%(method, m["error"]))
    return m["result"]

def ready(path, pid):
    def c():
        i=rpc(path,"getmodelnetworkinfo",[])
        return i if i.get("helper_ready") else None
    return wait_unix(c, timeout=20, pid=pid, log=path.parent.with_suffix(".log") if False else path.parent.parent/ (path.parent.name+".log"))

sa, sb = root/"a/modeld.sock", root/"b/modeld.sock"
wait_unix(lambda: rpc(sa,"getmodelnetworkinfo",[]) if (sa.exists()) else None, timeout=20, pid=pa, log=root/"a.log")
wait_unix(lambda: rpc(sb,"getmodelnetworkinfo",[]) if (sb.exists()) else None, timeout=20, pid=pb, log=root/"b.log")
info=rpc(sa,"getmodelnetworkinfo",[])
print("openssl", info.get("openssl"), "group", info.get("group"), "cipher", info.get("cipher"))
if "3.5.8" not in str(info.get("openssl")):
    raise SystemExit("helper not on 3.5.8: "+json.dumps(info))
if info.get("group")!="MLKEM768" or info.get("cipher")!="TLS_AES_256_GCM_SHA384":
    raise SystemExit("PQ-19 weakened: "+json.dumps(info))
if not info.get("pq1_ready"):
    raise SystemExit("pq1_ready false: "+json.dumps(info))
imp=rpc(sa,"importmodel",[str(root/"a/src"),{"pin":True}])
rpc(sb,"addmodelnode",[f"127.0.0.1:{port}"])
got=rpc(sb,"getmodel",[imp["uri"],"FREE_ONLY"])
if got.get("job_id"):
    poll_job(lambda: rpc(sb,"getmodeljob",[got["job_id"]]), timeout=30)
listed=rpc(sb,"listmodels",[])
if int(listed.get("local_count") or 0)<1:
    raise SystemExit(listed)
print("E2E_OPENSSL358 PASS", json.dumps({"openssl": info.get("openssl"), "group": info.get("group"), "uri": imp["uri"]}))
PY
echo "E2E_OPENSSL358 PASS (second-process; production btxd.real untouched)"
