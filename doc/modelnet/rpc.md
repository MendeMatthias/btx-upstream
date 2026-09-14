# Model RPC catalogue

`btxd` (when `-DWITH_MODELNET=ON`) proxies these to `btx-modeld` via
`-modelrpcsocket`. If the helper is down, calls **fail closed**. The same
methods are available directly on the helper unix socket (researcher
profile, no `btxd`).

## Implemented in this tree

| RPC | Role |
|---|---|
| `getmodelnetworkinfo` / `getmodelcryptoinfo` | Schema 2, OpenSSL identity, PQ1 flags, **capabilities**, `automatic_spend_atoms=0` |
| `decoderesource` / `encoderesource` / `decoderesourceuri` / `encoderesourceuri` | Compact URI; no network |
| `openbtxuri` | Preview-only; never inference / mining / wallet |
| `resolveresource` | Typed lookup; coverage incomplete |
| `importmodel` | Stream hash + 4 MiB pieces; optional pin. Never executes pickle/.pt |
| `listmodels` / `searchmodels` | Local catalog (`coverage` may be `incomplete`; `remote_count` may be 0) |
| `getmodelmanifest` | Verified metadata |
| `exportmodelpath` | Verified local store paths; never starts a runtime |
| `seedmodel` / `unseedmodel` | Manual serve / stop. Default `seed=auto` already seeds after import/`getmodel` |
| `qualifymodel` | Structure only |
| `getmodel` | `FREE_ONLY` retrieve (URI or digest48); demand-seeds when `seed=auto` |
| `getmodelpolicy` / `setmodelpolicy` | Free-first + propagation (`seed`, `preserve_rare`); non-zero automatic spend and `auto_pay` are refused |
| `addmodelnode` / `getmodelpeers` | Model-plane contacts, not AddrMan |
| `exportmodelcontacts` / `importmodelcontacts` / `exportmodelpeers` / `importmodelpeers` / `importmodeltrust` | Public endpoints; download cannot modify trust |
| `getmodeljob` / `cancelmodeljob` | Stub job list (`coverage: incomplete`) |
| `listmodelidentities` / `createmodelidentity` | Identity-only ML-DSA keys; never wallet keys |
| `listmodelrules` / `setmodelrule` / `removemodelrule` | Model ACL; never BanMan |
| `joinmodelcircle` / `leavemodelcircle` / `subscribemodelcollection` / `subscribemodelpolicy` | Local community policy; no on-chain membership |
| `delegatemodelservice` / `revokemodelservice` | Typed service ops; never a money signature |
| `getmodelreciprocity` | Local useful-byte observations; not money |
| `createmodelrelease` / `pledgemodelrelease` / `getmodelrelease` | Local campaign objects; SHA-256 `key_hash` only |
| `claimmodelrelease` / `refundmodelrelease` | Pointers to 0.34.6 `buildhtlcclaim` / `buildhtlcrefund` |

Peer HTTP (PQ1): [http.md](http.md). `getmodelnetworkinfo` → `capabilities.http`
lists every implemented path. `capabilities.features` is `127` (v1.1 core
profile bits).

POST `/btx-model/2/quotes` records a prepaid quote. POST `.../payment` journals a txid and **refuses duplicate txids**. The helper does not verify the chain and does not spend.

## Still `NOT_IMPLEMENTED` (wallet-side)

`preparemodelfunding`, `signmodelfunding`, `submitmodelfunding`,
`exportmodelrecovery`, `buildmodelhtlcclaim`, `buildmodelhtlcrefund`.

These names **are registered** so `btx-cli help <name>` works; they return a
stable `NOT_IMPLEMENTED` error. Use 0.34.6 `buildhtlcclaim` / `buildhtlcrefund`
for SHA-256 HTLCs. `htlc_tx` remains recovery-only.

## Isolation

`addmodelnode` is not monetary `addnode`. Model RPCs never sit on the
validation hot path. See [isolation.md](isolation.md).
