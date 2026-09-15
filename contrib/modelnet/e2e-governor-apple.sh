#!/usr/bin/env bash
# Apple Silicon E2E. NOT_RUN unless BTX_GOV_APPLE_E2E=1.
set -euo pipefail
if [[ "${BTX_GOV_APPLE_E2E:-}" != 1 ]]; then
  echo "NOT_RUN: set BTX_GOV_APPLE_E2E=1 on Apple Silicon"
  exit 0
fi
exit 1
