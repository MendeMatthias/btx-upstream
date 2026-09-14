# How to test and use 0.34.7 model hosting

This is the operator/researcher guide for **using** and **proving** the
Native Model Network in this tree. Packaged `acceptance-matrix.csv` stays
**NOT_RUN** (DOC-04). Re-run the scripts; do not treat a green CSV as the bar.

**Fail-fast:** every script below exits on the first error. Do not wait
minutes after a `FAIL` / `retrieve failed` line.

## What you get

A BTX node already has compute. `btx-modeld` gives it **models**; `btxd`
gives it **money**. They are two processes. Strict PQ1 or the helper
fail-closes. If the helper dies, monetary BTX stays up.

Defaults after a **positive** `-modelstorage` / `-modelcache`:

| Knob | Default | Meaning |
|---|---|---|
| `-modelseed` | `auto` | Demand-seed: an intentional `importmodel` / `getmodel` is retained and re-advertised inside quota |
| `-modelseedupondownload` | B0 **alias** of seed off/auto | **Not** a second opt-in gate |
| preserve-rare | off | Unsolicited fetch of under-replicated models stays explicit (`-modelpreserverare`) |
| automatic spend | 0 | `FREE_ONLY` never becomes paid because a timer expired |

`seedmodel` is only for `-modelseed=manual`.

## Build (one compile tree)

```bash
df -h /   # stop if <20G free
cmake -B build-gcc13 -DCMAKE_BUILD_TYPE=Release -DBUILD_GUI=OFF -DBUILD_BENCH=OFF
cmake --build build-gcc13 --target btx-modeld btx-modelcheck btx-open test_btx
# never a second -j$(nproc) on this host
# GUI (same tree, not a second Debug tree):
#   apt install qt6-base-dev qt6-tools-dev librsvg2-bin libqrencode-dev
#   cmake -B build-gcc13 -DBUILD_GUI=ON -DWITH_QT_VERSION=6
#   cmake --build build-gcc13 --target btx-qt test_btx-qt
```

OpenSSL **3.5+** with ML-KEM-768 and ML-DSA-44 is required for PQ1. System
3.0 cannot host. On those hosts use `contrib/modelnet/run-modeld.sh` with
bundled `lib/`.

## In-tree test suite (fail-fast)

| What | Command | Proves |
|---|---|---|
| Library (254 `modelnet_*` cases) | `build-gcc13/bin/test_btx --run_test=modelnet_*` | Spec rows: URI, PQ, STORE, FREE, DISC, ISO, SCRIPT leaves, demand-seed default, grant headers, grant expiry |
| Reference codecs | `python3 -m unittest -v test_v11` in `contrib/modelnet/reference` | URI/record vectors |
| Full local process suite | `contrib/modelnet/e2e-all.sh` or `e2e-parallel-a.sh` + `e2e-parallel-b.sh` | Two-helper PQ1, local helper, resolve 8/4, NAT resume, preserve-rare, two-source, first-run, DISC-05 failover, §12.3 bench, OpenSSL 3.5.8 second-process, TLS 512, GUI URI source, DOC, optional Chrome |
| Concurrent two-host wave | `contrib/modelnet/e2e-parallel-hosts.sh` | Isolated CUDA worker + two-host regtest + Chrome + production PID watch |
| Cross-host inspect | `contrib/modelnet/e2e-cross-host-inspect.sh` | granite bytes match (13888336427) + production PIDs + GPU still holds ExactReplay |
| Isolated CUDA worker | `contrib/modelnet/cuda-isolated-e2e.sh` | Tiny kernel on a dedicated CUDA workstation only; never the live attestor GPU |
| Granite FIT vs ExactReplay | `contrib/modelnet/e2e-cuda-granite-fit.sh` | Isolated worker: 13.8 GiB would FIT; live ExactReplay reserve is not starved |
| One-node regtest + helper | `python3 test/functional/feature_modelnet_helper.py --configfile=build-gcc13/test/config.ini --timeout-factor=1` | `btxd -regtest` + unix helper; import demand-seeds; EXPLICIT_PAID is WALLET_REQUIRED |
| HTLC (0.34.6 reuse) | **Direct file**, ASCII tmpdir (do **not** use `test_runner.py` cache): `mkdir -p /tmp/btx-htlc/atomicswap && python3 test/functional/wallet_htlc_atomicswap.py --descriptors --configfile=build-gcc13/test/config.ini --tmpdir=/tmp/btx-htlc/atomicswap --timeout-factor=1` | SCRIPT-03/09/11 claim mined + preimage on-chain; wrong preimage refused; refund after locktime. Same pattern: `wallet_modelnet_funding.py` |
| Two-host isolated regtest | `contrib/modelnet/e2e-regtest-two-host.sh` | Second-process `btxd -regtest` + `btx-modeld`; production PIDs untouched |
| Two WAN seeders | `contrib/modelnet/e2e-two-wan.sh` | STORE-01: fetcher next to two seeders (same OpenSSL); resume `local` |
| Two-node WAN (tiny / granite) | `BTX_WAN_E2E=1 SEEDER=host:port contrib/modelnet/e2e-two-node-demand.sh` | Real PQ1 upload/download. Fetcher **must not** pass `-modelseed=auto` or `seedmodel` |
| Introducer death | `contrib/modelnet/e2e-disc-failure.sh` | DISC-04 no official names; DISC-05 same job fails over after introducer RST (helper ignores SIGPIPE) |
| §12.3 bench | `contrib/modelnet/e2e-bench-12-3.sh` | Writes `e2e-scratch/bench-12-3/bench.json` |
| Hashed evidence | `contrib/modelnet/e2e-production-evidence.sh` | SHA-256 of binaries + bench JSON. Does not flip the CSV |

Do **not** run granite into `/tmp` (tmpfs). Do **not** `getmodel` granite on
the live attestor helper.

### Fail-fast rule

- `getmodeljob` status `failed` → print the error and **exit** (no remaining timeout).
  While `status=running`, `last_err` / `peer_retries` / `bytes_committed` may
  show a transient `tls io`; that is resume, not a FAIL.
- Prefer loopback or LAN to the seeder (`127.0.0.1:29448` when fetcher and
  seeder are the same host). Hairpin through a public hostname is not the
  retrieve test.
- Helper process gone or log `unknown argument` / `fail-closed` → **exit** (do not wait for the socket).
- Handshake/grant errors surface as `hello failed`, `missing FreeGrant`,
  `piece HTTP 403 … expired` (client then refreshes the 600s FreeGrant).
- Production `btxd.real` PIDs are checked before and after two-host scripts.

## Benchmarks (re-run, do not guess)

Loopback 32 MiB two-helper (`e2e-bench-12-3.sh`), observed:

| Field | Value |
|---|---|
| payload_bytes | 33554507 |
| elapsed_s | ≈ 1.185 |
| first_useful_byte_s | ≈ 0.413 |
| verified_throughput_mib_s | ≈ 27.0 |
| free_completion_share | 1.0 |
| independent_contacts | 1 |

WAN granite (13 888 336 427 bytes) on a dedicated seeder/fetcher pair has
completed at **BYTES_VERIFIED** / `seeded=true`. A prior full retrieve was
≈ 6562 s (≈ 2.1 MB/s). Re-run `e2e-two-node-demand.sh` on a fresh-buyer
datadir for a new number; do not `getmodel` on the live attestor helper.

OpenSSL **3.5.8** is proven as a **second-process** helper via
`e2e-openssl-358.sh` (`LD_LIBRARY_PATH` + hostile `OPENSSL_CONF` still
reports MLKEM768). Relinking production `btxd.real` is a separate operator
step; do not swap a running signer binary.

## User scenarios (use)

### 1. Researcher, zero wallet (no chain)

```bash
build-gcc13/bin/btx-modelcheck /path/to/model.safetensors
build-gcc13/bin/btx-modeld \
  -modeldir=./modelnet-data \
  -modelstorage=80GiB \
  -modelbind=127.0.0.1:29447 \
  -modelhost
```

Unix RPC is **one JSON line**:

```json
{"jsonrpc":"1.0","id":1,"method":"importmodel","params":["/path/to/dir",{"pin":true}]}
{"jsonrpc":"1.0","id":1,"method":"listmodels","params":[]}
{"jsonrpc":"1.0","id":1,"method":"getmodelnetworkinfo","params":[]}
```

Expect `propagation.demand_propagation=true` and `seed_upon_download_opt_in=false`.
Import `seeded=true` without `seedmodel`.

Point a **local** runtime at `exportmodelpath`. BTX does not start inference
and does not expose it to the network.

### 2. Second helper downloads free

```json
{"jsonrpc":"1.0","id":1,"method":"addmodelnode","params":["127.0.0.1:29447"]}
{"jsonrpc":"1.0","id":1,"method":"getmodel","params":["btx://<91-char-token>","FREE_ONLY"]}
```

If `status=running`, poll `getmodeljob`. On WAN this is async. Loopback
smoke: `python3 contrib/modelnet/two_helper_retrieve.py build-gcc13/bin`.

### 3. Two machines (isolated, not production)

```bash
contrib/modelnet/e2e-regtest-two-host.sh
```

Starts **new** `btxd -regtest` datadirs and **new** helpers. Production
`btxd.real` stays up. Fetcher command line has no `-modelseed=auto`.

### 4. Large model (granite-scale)

FreeGrant TTL is **600s** (spec cap). The client **refreshes** the grant when
a piece GET returns HTTP 403 `expired`. Resume is automatic: present
`.piece` files are skipped.

```bash
BTX_MODELD_DIRNAME=e2e-granite BTX_WAN_E2E=1 \
  SEEDER=203.0.113.10:29448 URI=btx://… \
  contrib/modelnet/e2e-two-node-demand.sh
```

Use a dedicated seeder port. Never the live attestor datadir.

### 5. Manual seed only

```bash
btx-modeld -modelstorage=80GiB -modelseed=manual …
# then seedmodel / unseedmodel
```

### 6. Preserve-rare (unsolicited)

```bash
btx-modeld -modelstorage=80GiB -modelpreserverare …
```

One preservation job at a time. Not the default. Do not set this on a
signer/attestor.

### 7. Paid / HTLC (optional money)

`EXPLICIT_PAID` is WALLET_REQUIRED until a monetary wallet is configured.
`getmodel FREE_FIRST_APPROVAL` journals a quote without spending.
Helper `preparemodelfunding` is `NOT_IMPLEMENTED` by design; reuse 0.34.6
`buildhtlcclaim` / `buildhtlcrefund`. HASH160 `htlc_tx` is recovery-only.

### 8. Models URI / GUI

`btx://` is a **model resource**, never a payment. `PaymentServer` emits
`receivedModelResource` **before** `parseBitcoinURI` / `DecodeDestination`.
The Models page shows the URI (`showOpenedUri`); it does not auto-`getmodel`.
Linux: `contrib/modelnet/e2e-os-handler.sh` (`btx-open`, `x-scheme-handler/btx`).

```bash
contrib/modelnet/e2e-gui-uri.sh
```

`btx-qt` needs Qt 6 headers in the **same** `build-gcc13` tree
(`-DBUILD_GUI=ON -DWITH_QT_VERSION=6`). Offscreen: `QT_QPA_PLATFORM=offscreen`.

### 9. Optional browser bridge (never native PQ)

PQ-only deployments **omit** the bridge. Native `btx-modeld` never speaks
classical HTTPS.

```bash
contrib/modelnet/e2e-bridge-optional.sh          # local CA + Chrome
contrib/modelnet/e2e-public-webpki-kit.sh        # operator DNS + public CA steps
```

Public WebPKI needs an operator hostname and a real CA. The kit generates
the CSR layout and proves the local-CA path. It does not invent a public
certificate.

### 10. CUDA qualification (optional, isolated)

Static `btx-modelcheck` never launches kernels. A CUDA worker **must** be a
separate process from `btxd` and must not starve ExactReplay.

```bash
# dedicated CUDA workstation only. Tiny kernel. Production ExactReplay stays on the GPU.
contrib/modelnet/cuda-isolated-e2e.sh
# GPU-02: missing --gpu / gpu=99 / gpu=0 without --allow-shared-gpu all fail
# GPU-01/03/04/05/06: kernel, isolation, 8s alarm, crash isolation, backend hash
```

Never run CUDA on the live attestor. `capabilities.cuda_qualification=false`
until that isolated worker is compiled and run.

### 11. Recovery

See [recovery.md](recovery.md). Helper crash: restart `btx-modeld` on the
same `-modeldir`; committed pieces remain. Monetary node is independent.

## Isolation (do not violate)

- Do not `systemctl --user stop` production `btxd` on the live attestor.
- Do not `SIGKILL` production `btxd`.
- Do not `getmodel` granite into `~/.btx`.
- Do not name operator hostnames or seeder IPs in **public** trees.
- One `-j$(nproc)` compile. `/tmp` is RAM.

## Spec map

Normative text is the v1.1 root addendum, then B0. In-tree tests live under
`src/test/modelnet_*.cpp`. Process proofs are `contrib/modelnet/e2e-*.sh`
and `test/functional/feature_modelnet_helper.py`. This HOWTO is how you
**run** them, not a rewrite of B0.
