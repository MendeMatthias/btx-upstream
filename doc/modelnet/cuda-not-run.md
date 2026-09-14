# CUDA / runtime GPU qualification

GPU runtime qualification is **not** a proof of model usefulness or safety.
Capabilities report `cuda_qualification=false`. Group M is **NOT_RUN**.

## Policy

- Static qualification (`btx-modelcheck` / `QualifyFile`) never launches
  CUDA kernels. It reads SafeTensors/GGUF **headers** vs filesystem size.
- Pickle / `.pt` / Python / `.so` are rejected before any runtime.
- A future CUDA worker MUST be a separate process from `btxd` and MUST
  not contend with a live mining/ExactReplay GPU.
- Shared validation GPUs remain B0-restricted: model qualification must
  not starve ExactReplay.

Do not treat a `STRUCTURE_VERIFIED` shard as “it runs on this GPU.”
