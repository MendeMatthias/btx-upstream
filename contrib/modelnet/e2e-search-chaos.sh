#!/usr/bin/env bash
# Chaos harness stub for search/indexer failure modes. Not run in CI by default.
set -euo pipefail
export LC_ALL=C

if [[ "${BTX_SEARCH_CHAOS:-}" != "1" ]]; then
  cat <<'EOF'
NOT_RUN: chaos search lab disabled (export BTX_SEARCH_CHAOS=1 to acknowledge hazards).

Planned chaos steps (manual / future automation):
  1. Start 3+ btx-modeld helpers on /tmp unix sockets with overlapping search records.
  2. Run searchmodels scope=NETWORK while randomly SIGTERM one indexer mid-query.
  3. Verify coverage.complete stays false and client returns partial results (no hang).
  4. Partition model-plane TCP (iptables or netns) while LOCAL search still answers.
  5. Flood publishmodelsearchrecord to trigger publisher spam cap (>64 / publisher window).
  6. Import conflicting sequences via importmodelindex; expect higher sequence wins.
  7. Kill all indexers; confirm LOCAL scope on a merged client still serves cached records.
  8. rm -rf /tmp/test_runner_* and /tmp/btx-search-chaos-* on exit (tmpfs hygiene).

Requires: built btx-modeld, operator supervision, TIMEOUT_FACTOR=1, single runner.
Does not target production btxd.
EOF
  exit 2
fi

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
BIN="${BIN_DIR:-$ROOT/build-gcc13/bin}"
MODELD="${MODELD:-$BIN/btx-modeld}"

cleanup() {
  rm -rf /tmp/test_runner_*
  rm -rf /tmp/btx-search-chaos-*
}
trap cleanup EXIT

if [[ ! -x "$MODELD" ]]; then
  echo "NOT_RUN: btx-modeld missing at $MODELD" >&2
  exit 2
fi

echo "BTX_SEARCH_CHAOS=1 set but automated chaos steps are not implemented yet." >&2
echo "Follow the documented steps above; exiting NOT_RUN." >&2
exit 2
