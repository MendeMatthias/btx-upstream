# CUDA / RTX 5060 Ti qualification

GPU runtime qualification is **not** a proof of model usefulness or safety.
This document records why the 0.34.7 private tree marks group M **NOT_RUN**
on the implementation host.

## This host

- `nvidia-smi` is unavailable (no working NVIDIA driver in this userspace).
- `nvcc` is not on PATH.
- macpro2 is the live canonical GPU / attestation authority. Do not starve
  its mining GPU, do not reboot it, and do not run CUDA goldens against it
  for modelnet work.

## Policy

- Static qualification (`btx-modelcheck`) never launches CUDA kernels.
- Pickle / `.pt` / Python / `.so` are rejected before any runtime.
- A future CUDA worker must be a separate process from `btxd`.
