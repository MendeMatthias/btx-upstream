# BCP/1 certification harness

BTX Custody Profile 1 / `BTX_EXCHANGE_PROFILE_V1`: a **regtest** environment that exercises the monetary custody surface without HCP, Model Network, mining, GUI, or GPU.

Public docs:

- [doc/integrations/README.md](../../doc/integrations/README.md) — integration docs index
- [doc/integrations/exchange-custody.md](../../doc/integrations/exchange-custody.md) — FAQ (UTXO, watch-only, deposit pool, no GPU/HCP/modelnet)
- [doc/integrations/bcp1.md](../../doc/integrations/bcp1.md) — `BTX_EXCHANGE_PROFILE_V1`, RPCs, events, confirmation/reorg (`getdepositstatus`, wallet reorg hold)
- [doc/integrations/external-sign.md](../../doc/integrations/external-sign.md) — unsigned → digest → sign → insert → validate → broadcast; BTXPSBT; `SignerProvider`
- [doc/integrations/key-link.md](../../doc/integrations/key-link.md) — Stage 1 raw/PQ signing vs native venue asset (vendor product)
- [doc/integrations/incident-recovery.md](../../doc/integrations/incident-recovery.md) — reorg un-credit, crash, signer down, pool restore
- [network-manifest.json](network-manifest.json) — mainnet P2P 19335, RPC 19334, HRP `btx`, genesis, magic `b7545801`, 90s block interval, dust/fees, `MAX_MONEY` 21M BTX

Build monetary-only nodes with **`-DWITH_MODELNET=OFF`** (no CUDA, no `btx-modeld`, no GUI). That is the same profile a listing team audits: `btxd`, `btx-cli`, watch-only wallet, external signer, ZMQ — not Model Network RPCs.

Optional local container (host-side compile is usually faster; Dockerfile builds `-DWITH_MODELNET=OFF` inside the image):

```bash
docker build -f contrib/bcp1/Dockerfile -t btx:exchange-local .
```

The resulting image is **`btx:exchange-local`**: `btxd` + `btx-cli` only. A release might publish something like `ghcr.io/btxchain/btx:exchange-v0.x.y`; **this tree does not push to ghcr or any registry.**

This directory is vendor-neutral. Adapters may speak PKCS#11, HTTPS, or a command signer; venue/Key-Link product names are examples, not consensus.

---

## What `docker compose` brings up

From this directory (or the repo root with `-f contrib/bcp1/docker-compose.yml`):

```bash
# Sidecars on loopback (mock HTTPS signer + webhook receiver)
docker compose -f contrib/bcp1/docker-compose.yml up mock-signer webhook

# Run certification and print PASS rows (needs host BTXD=… or build-gcc13/bin/btxd)
BTXD=/path/to/btxd docker compose -f contrib/bcp1/docker-compose.yml up cert-runner
```

Compose services (loopback only; never ports **18443/18444**; never **`/var/lib/btxd`**):

| Service | Role |
|---|---|
| `mock-signer` | `mock_signer.py` HTTP adapter on `127.0.0.1:18781` |
| `webhook` | Test webhook receiver on `127.0.0.1:18782` |
| `cert-runner` | Runs `./run-certification.sh` → `=== BCP/1 PASS rows ===` and `N/13 PASS` (no CUDA image; mount repo + host `btxd`) |
| `btxd` (profile `node`) | Optional long-running regtest node on **39443/39444** with bind-mounted monetary-only binary |

The functional harness (`test/functional/feature_bcp1.py`) still covers watch-only wallet, deposit/withdrawal generators, reorg simulation, and ZMQ — inside isolated regtest started by the test framework or `run-certification.sh`. Do not point compose at a mainnet datadir. Do not publish signer endpoints beyond loopback.

---

## `./run-certification`

```bash
cd contrib/bcp1
./run-certification
```

The script drives the compose stack (or an already-running local regtest) and prints `PASS` / `FAIL` per case. Named cases:

| Case | What must hold |
|---|---|
| address generation | Pool / `getp2mrpubkeys` / `deriveexchangeaddress` — no fake BIP32 xpub |
| deposit detection | `getdepositstatus` → `MEMPOOL`; optional `-walletdepositnotify` `deposit.detected` |
| 1→N confirmations | Depth 1 = included in a connected block; depth grows on further connects |
| reorg handling | Disconnect → `REORGED`; credit logic un-credits without restart |
| unsigned withdrawal | `createpsbt` → `prepareexternalsign` → `getsigningdigests` |
| external PQ signature | Mock `SignDigest` (ML-DSA-44) |
| signature import | `finalizeexternalsign` (no broadcast) |
| broadcast | `testmempoolaccept` then `sendrawtransaction` |
| batch withdrawal | One tx, many outputs, change |
| UTXO consolidation | `planconsolidation` / `createconsolidationtx` |
| double-spend rejection | Conflicting spend is `CONFLICTED` / mempool-reject |
| node restart | Status and UTXOs survive; restart-only recovery is FAIL |
| wallet recovery | Watch-only restore from descriptors / deposit pool |

Corrupt ML-DSA signatures and wrong prevouts must FAIL `finalizeexternalsign` / `testmempoolaccept`.

A clean run prints a profile summary, for example:

```text
BTX Exchange Integration Profile v1 (BCP/1)
13/13 PASS
```

(The count follows the cases actually implemented in `run-certification.sh` / `test/functional/feature_bcp1.py`, not a marketing total.)

---

## Local (no Docker)

Same contract, isolated regtest:

```bash
btxd -regtest -txindex=1 -exchange-watchonly \
  -zmqpubsequence=tcp://127.0.0.1:28332 \
  -signer=./contrib/bcp1/mock_signer.py
./contrib/bcp1/run-certification
```

Functional coverage also lives in `test/functional/feature_bcp1.py` (`--timeout-factor=1`). One `test_runner.py` at a time. Delete `/tmp/test_runner_*` when finished.

---

## Out of scope

- Production `btxd`, CUDA, or any live attestor
- HCP / `btx-modeld` / Cognitive Reserve
- Native venue asset listing (stage 2) and Key-Link + ML-DSA-44 (open vendor question, not a PASS)
- Operator hostnames
