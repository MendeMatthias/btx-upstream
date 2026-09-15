#!/usr/bin/env bash
# ECON GUI source contract: feed tabs, Fund Release, economy RPCs (extends e2e-gui-gates).
set -euo pipefail
export LC_ALL=C
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
die() { echo "e2e-economy-gui: $*" >&2; exit 1; }
PAGE="$ROOT/src/qt/modelnetpage.cpp"
UI="$ROOT/src/qt/forms/modelnetpage.ui"
grep -n 'getmodelfeed' "$PAGE" >/dev/null || die "getmodelfeed missing"
grep -n 'getmodeleconomyentry' "$PAGE" >/dev/null || die "getmodeleconomyentry missing"
grep -n 'preparefundmodelrelease' "$PAGE" >/dev/null || die "preparefundmodelrelease missing"
grep -n 'Fund Release' "$PAGE" >/dev/null || die "Fund Release button missing"
grep -n 'getrecentlyunlockedmodels' "$PAGE" >/dev/null || die "just-released RPC missing"
grep -n 'NEARLY_FUNDED' "$PAGE" >/dev/null || die "Nearly funded tab wiring missing"
grep -n 'name="tabScopeJustReleased"' "$UI" >/dev/null || die "Just Released tab missing"
grep -n 'Search open models' "$UI" >/dev/null || die "search placeholder missing"
"$ROOT/contrib/modelnet/e2e-gui-gates.sh"
echo "ECON-GUI source contract PASS"
