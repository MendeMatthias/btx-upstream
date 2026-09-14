#!/usr/bin/env bash
# V11-URI-12: OS handler is btx-open with exactly one URI. Extra args fail.
# XDG desktop file in scratch; does not install system-wide.
export LC_ALL=C
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
OPEN="${BIN_DIR:-$ROOT/build-gcc13/bin}/btx-open"
URI='btx://pqwy06q0q7wwzy70aeq45sxnlvq3mr067yt4jzphzvnfn2c4zc24zxz665zdprf0nwgskvqq9cq365u9n8l25'
die() { echo "e2e-os-handler: $*" >&2; exit 1; }
[[ -x "$OPEN" ]] || die "missing $OPEN"
out="$("$OPEN" "$URI")"
printf '%s\n' "$out" | grep -q 'action=preview-only' || die "preview"
printf '%s\n' "$out" | grep -q 'wallet=not-opened' || die "wallet"
set +e
"$OPEN" "$URI" extra >/dev/null 2>&1
rc=$?
set -e
[[ "$rc" -eq 1 ]] || die "extra args must fail rc=$rc"
DESK="$ROOT/e2e-scratch/os-handler"
mkdir -p "$DESK"
cat >"$DESK/btx-open.desktop" <<EOF
[Desktop Entry]
Name=BTX Open
Exec=$OPEN %u
Type=Application
MimeType=x-scheme-handler/btx;
NoDisplay=true
EOF
grep -q 'Exec=.*%u' "$DESK/btx-open.desktop" || die "desktop %u"
echo "E2E_OS_HANDLER PASS"
