# BTX 0.34.7 — Native Model Network (RC)

**Status:** proposed RC on the 0.34.6 monetary baseline. Packaged
`acceptance-matrix.csv` stays **NOT_RUN**. `CLIENT_VERSION` is **0.34.7**
with `CLIENT_VERSION_IS_RELEASE=false`.

A BTX node already has compute. 0.34.7 gives it **models and money** on an
isolated plane. Inference is **local after acquisition**. Remote/paid
inference is removed from the roadmap (v1.1 D01).

## What landed in this tree

- Compact `btx://` Bech32m URIs (SHA-384, kinds 0–8)
- Isolated `btx-modeld` / `btx-modelcheck` / `btx-open`
- Strict PQ1 TLS (ML-KEM-768, ML-DSA-44, AES-256-GCM-SHA384)
- Streaming import, 4 MiB verified pieces, free-first retrieve
- Demand-seed default once a storage budget is allocated (D11); unsolicited fetch remains opt-in
- Default automatic spend **0**; paid RPCs honestly `NOT_IMPLEMENTED`
- Default automatic spend **0**; paid RPCs honestly `NOT_IMPLEMENTED`
- HTLC reuse of 0.34.6 `htlc_sha256` / `buildhtlcclaim` / `buildhtlcrefund`

## What did not change

- ExactReplay, fork choice, issuance, BanMan, AddrMan
- No new HTLC opcode; HASH160 `htlc_tx` remains recovery-only

## Compatibility

Build: `-DWITH_MODELNET=ON` (default). OpenSSL 3.5+ required for the
helper. See [doc/modelnet/README.md](../modelnet/README.md).

## Upgrade notes

`btxd` does not replace a running signer. Run `btx-modeld` as a **second
process** with its own `-modeldir`. Helper crash leaves monetary BTX up.
