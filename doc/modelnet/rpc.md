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
| `getmodeljob` / `cancelmodeljob` | Job list with `status`, `bytes_committed`, `pieces_committed`, `file_index`, `piece_index`, `inflight`, `peer_retries`, `last_err`, catalog `used_bytes` |
| `listmodelidentities` / `createmodelidentity` | Identity-only ML-DSA keys; never wallet keys |
| `listmodelrules` / `setmodelrule` / `removemodelrule` | Model ACL; never BanMan |
| `joinmodelcircle` / `leavemodelcircle` / `subscribemodelcollection` / `subscribemodelpolicy` | Local community policy; no on-chain membership |
| `delegatemodelservice` / `revokemodelservice` | Typed service ops; never a money signature |
| `getmodelreciprocity` | Local useful-byte observations; not money |
| `createmodelrelease` / `pledgemodelrelease` / `getmodelrelease` | Local campaign objects; SHA-256 `key_hash` only |
| `claimmodelrelease` / `refundmodelrelease` | Demand-seed + pointer to `buildmodelhtlcclaim` / `buildmodelhtlcrefund` |
| `preparemodelfunding` / `signmodelfunding` / `submitmodelfunding` / `exportmodelrecovery` | Freeze exact `htlc_sha256` round. Helper never auto-spends; helper sign is complete=false without keys; helper submit journals (no chain verify). `btxd` wallet signs and broadcasts. |
| `buildmodelhtlcclaim` / `buildmodelhtlcrefund` | Unsigned 0.34.6 SHA-256 HTLC templates. SHA-256(preimage) must match `key_hash`. HASH160 `htlc_tx` is recovery-only. |

Peer HTTP (PQ1): [http.md](http.md). `getmodelnetworkinfo` → `capabilities.http`
lists every implemented path. `capabilities.features` is `127` (v1.1 core
profile bits).

POST `/btx-model/2/quotes` records a prepaid quote. POST `.../payment` journals a txid and **refuses duplicate txids**. The helper does not verify the chain and does not spend.

## Isolation

`addmodelnode` is not monetary `addnode`. Model RPCs never sit on the
validation hot path. See [isolation.md](isolation.md).
