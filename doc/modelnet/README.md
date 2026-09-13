# BTX Native Model Network (0.34.7)

A BTX node already has compute. BTX gives it models and money.

This is **not** a remote inference marketplace. Inference runs **locally**
after a model is acquired. The model plane has no effect on block validity,
fork choice, work, difficulty, mining priority, transaction consensus,
ExactReplay, or issuance.

## Binaries

- `btxd` — monetary node. Optional introduction bridge (`-modelnet`).
- `btx-modeld` — isolated helper. Strict PQ1 or fail closed. Monetary BTX
  stays up if this process dies.
- `btx-modelcheck` — static SafeTensors/GGUF qualification. Never executes
  Pickle, `.pt`, Python, or CUDA kernels.

## Retrieval

Default automatic BTX spend is **zero**. Free-first, reciprocal-first,
market-second. Paid retrieval requires an explicit budget or approval and
reuses final 0.34.6 `htlc_sha256` / `buildhtlcclaim` / `buildhtlcrefund`.
HASH160 `htlc_tx` is recovery-only.

## Isolation

- Model allow/deny never BanMan-punishes a valid monetary peer except genuine
  cross-plane abuse.
- `NODE_MODEL_RELAY` / `NODE_MODEL_HOST` are unauthenticated hints. They are
  not in `SeedsServiceFlags()` and do not make `MayHaveUsefulAddressDB` true.
- Artifact endpoints are never inserted into monetary AddrMan.
- CPU-only discovery relays have zero monetary-consensus authority.

See also: [uri.md](uri.md), [pq-transport.md](pq-transport.md),
[htlc-reuse.md](htlc-reuse.md), [isolation.md](isolation.md).
