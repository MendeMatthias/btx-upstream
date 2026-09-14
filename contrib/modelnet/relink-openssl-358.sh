#!/usr/bin/env bash
# Second-process OpenSSL 3.5.8 runtimes. Does NOT replace a running
# production btxd.real. Does not cmake a second tree.
set -euo pipefail
PREFIX="${OPENSSL358_PREFIX:-$HOME/.local/opt/openssl-3.5.8}"
ROOT="${ROOT:-$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)}"
BUILD="$ROOT/build-gcc13"
DEST="${DEST:-$BUILD/openssl358-second}"
mkdir -p "$DEST"
export LD_LIBRARY_PATH="$PREFIX/lib:${LD_LIBRARY_PATH:-}"
"$PREFIX/bin/openssl" version
for b in btx-modeld test_btx btx-open btx-cli; do
  if [[ -x "$BUILD/bin/$b" ]]; then
    cp -a "$BUILD/bin/$b" "$DEST/$b.real"
    cat >"$DEST/$b" <<EOF
#!/usr/bin/env bash
export LD_LIBRARY_PATH="$PREFIX/lib:\${LD_LIBRARY_PATH:-}"
exec "\$(dirname "\$0")/$b.real" "\$@"
EOF
    chmod +x "$DEST/$b"
  fi
done
echo "wrappers in $DEST"
ldd "$DEST/btx-modeld.real" | grep -E 'libssl|libcrypto' || true
echo "Run helpers as $DEST/btx-modeld (LD_LIBRARY_PATH=3.5.8). Do not swap live btxd.real."
