#!/usr/bin/env bash
# Isolated -regtest btxd (second process) proving economy RPCs through btx-cli.
# Never touches production btxd.
set -euo pipefail
export LC_ALL=C
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
BIN="${BIN:-$ROOT/build-gcc13/bin}"
WORKDIR="${WORKDIR:-/tmp/btx-econ-regtest-$$}"
rm -rf "$WORKDIR"
mkdir -p "$WORKDIR/node"
BTXD="$BIN/btxd"
CLI="$BIN/btx-cli"
MODELD="$BIN/btx-modeld"
test -x "$BTXD" && test -x "$CLI" && test -x "$MODELD"
DATADIR="$WORKDIR/node"
PID=""
cleanup() {
  local rc=$?
  if [[ -n "${PID:-}" ]] && kill -0 "$PID" 2>/dev/null; then
    "$CLI" -regtest -datadir="$DATADIR" -rpcuser=u -rpcpassword=p stop >/dev/null 2>&1 || true
    for i in $(seq 1 40); do
      kill -0 "$PID" 2>/dev/null || break
      sleep 0.1
    done
    if kill -0 "$PID" 2>/dev/null; then
      kill -TERM "$PID" 2>/dev/null || true
      sleep 1
    fi
  fi
  rm -rf "$WORKDIR" /tmp/test_runner_* 2>/dev/null || true
  exit "$rc"
}
trap cleanup EXIT

"$BTXD" -regtest -datadir="$DATADIR" -listen=0 -server=1 \
  -rpcuser=u -rpcpassword=p -fallbackfee=0.0001 \
  -modelhelper="$MODELD" -daemon=0 \
  >"$WORKDIR/btxd.log" 2>&1 &
PID=$!
ok=0
for i in $(seq 1 80); do
  if "$CLI" -regtest -datadir="$DATADIR" -rpcuser=u -rpcpassword=p getblockchaininfo >/dev/null 2>&1; then
    ok=1
    break
  fi
  sleep 0.25
done
test "$ok" = 1
info="$("$CLI" -regtest -datadir="$DATADIR" -rpcuser=u -rpcpassword=p getmodelnetworkinfo)"
echo "$info" | python3 -c 'import json,sys; j=json.load(sys.stdin); assert j.get("automatic_spend_atoms",1)==0'
ready=0
for i in $(seq 1 40); do
  info="$("$CLI" -regtest -datadir="$DATADIR" -rpcuser=u -rpcpassword=p getmodelnetworkinfo)"
  if echo "$info" | grep -q '"helper_ready": true'; then ready=1; break; fi
  sleep 0.25
done
test "$ready" = 1

MID="$(python3 -c 'print("a1"+"00"*47)')"
test "${#MID}" = 96
"$CLI" -regtest -datadir="$DATADIR" -rpcuser=u -rpcpassword=p publishmodelsearchrecord \
  "$MID" \
  '{"type":"btx-model-search-v1","canonical_name":"RegtestA17","display_name":"RegtestA17","short_description":"A specialized model for coding agents and repository tool use.","expires_at":0}'

sm="$("$CLI" -regtest -datadir="$DATADIR" -rpcuser=u -rpcpassword=p searchmodels '{"text":"coding agent","scope":"LOCAL"}')"
echo "$sm" | python3 -c 'import json,sys
j=json.load(sys.stdin)
assert j.get("automatic_spend_atoms",1)==0
names=[h.get("name") for h in (j.get("results") or [])]
assert "RegtestA17" in names, names
assert any(h.get("result_type")=="PUBLIC_MODEL" for h in (j.get("results") or [])), j
'
feed="$("$CLI" -regtest -datadir="$DATADIR" -rpcuser=u -rpcpassword=p getmodelfeed '{"scope":"LOCAL","mode":"NEWEST","limit":20}')"
echo "$feed" | python3 -c 'import json,sys
j=json.load(sys.stdin)
assert j.get("coverage",{}).get("global_complete") is not True
assert j.get("automatic_spend_atoms",1)==0
assert j.get("feed_sequence",0)>=1
'
econ="$("$CLI" -regtest -datadir="$DATADIR" -rpcuser=u -rpcpassword=p getmodeleconomyentry "$MID")"
echo "$econ" | python3 -c 'import json,sys
j=json.load(sys.stdin)
assert j.get("schema_version")==3
assert (j.get("lifecycle") or {}).get("state") or j.get("lifecycle_state")
assert j.get("automatic_spend_atoms")==0
'
"$CLI" -regtest -datadir="$DATADIR" -rpcuser=u -rpcpassword=p getblockchaininfo >/dev/null
echo "e2e-economy-regtest: PASS"
