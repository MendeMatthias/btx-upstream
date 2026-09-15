#!/usr/bin/env bash
# NVIDIA workstation E2E for the resource governor.
# Does not run unless BTX_GOV_NVIDIA_E2E=1. Never touches production btxd.
set -euo pipefail
if [[ "${BTX_GOV_NVIDIA_E2E:-}" != 1 ]]; then
  echo "NOT_RUN: set BTX_GOV_NVIDIA_E2E=1 on a dedicated NVIDIA workstation"
  exit 0
fi
echo "implement operator runbook: idle mine, yield to inference, ExactReplay, seed throttle"
exit 1
