# Architecture — isolated model helper

The model plane is a **separate process** from monetary validation.

```
btx-open / btx-cli / btx-qt
        |  local unix JSON-RPC
        v
   btx-modeld  <---- PQ1 TLS 1.3 /btx-model/2/ ----> peer btx-modeld
        ^
        |  optional proxy
      btxd  (-modelrpcsocket, -modelnet introduction hints only)
```

## Why two processes

v1.1 and B0 require that a helper crash, PQ failure, or corrupt store leave
ExactReplay, mempool, wallet, and issuance running. `btxd` must not take
`cs_main` for model hashing, TLS, or piece I/O.

`NODE_MODEL_RELAY` / `NODE_MODEL_HOST` are unauthenticated P2P hints
(`sendmodels` / `getmdpeers` / `mdpeers`). They are not in
`SeedsServiceFlags()`, do not make `MayHaveUsefulAddressDB` true, and never
insert artifact endpoints into AddrMan.

## Helper flags (`btx-modeld`)

| Flag | Meaning |
|---|---|
| `-modeldir=` | Catalog and piece store. Never wallet or chainstate. |
| `-modelstorage=` / `-modelcache=` | Payload quota. Default **0**. Accepts `80GiB` or raw bytes. Zero: no payload, no seeding, no preserve-rare. |
| `-modelseed=` | `auto` (default): demand-seed after intentional import/retrieve. `manual` / `off` disable auto-advertise. |
| `-modelpreserverare` | Opt-in fetch of qualified under-replicated models into spare quota. |
| `-modelbind=` | PQ1 listen `host:port`. Empty = unix RPC only. `-modelhost` defaults to `127.0.0.1:29447`. |
| `-modelrpcsocket=` | Unix JSON-RPC socket. |
| `-modeltransport=pq1` | Only accepted value; anything else fail-closes. |
| `-modeltlscert=` / `-modeltlskey=` | Self-signed ML-DSA-44 material (generated if missing). |
| `-modelhost` | Serve seeded artifacts. |
| `-modelrelay` | CPU-only discovery relay: no GPU, no wallet, no payload required. |
| `-decode=` | Decode a URI and exit. |

`btxd -modelrpcsocket=` defaults to `<datadir>/modelnet/modeld.sock`. If the
helper is down, model RPCs fail closed; monetary RPCs are unaffected.

## Native HTTP (`/btx-model/2/`)

HTTP/1.1 is framing. Authority is PQ1 + verified bytes.

| Endpoint | Body |
|---|---|
| `POST /hello` | Protocol/suite identity. Automatic spend reported as 0. |
| `GET /manifests/{id}` | Manifest JSON (hex IDs in URLs). |
| `GET /transfers/{id}/pieces/{file}/{piece}` | **Raw piece** `application/octet-stream` (≤ 4 MiB) plus `X-BTX-*` proof headers. Do not hex-encode the payload. |
| quotes / payment / releases | Not implemented in this tree; capabilities stay false. |

Connections keep-alive. Reconnect after 8 GiB or a stalled idle. TLS records
are size-bounded so WAN/NAT PMTU blackholes cannot stall a 4 MiB piece.

## Data on disk

Default helper layout under `-modeldir` (often `<datadir>/modelnet/` when
`btxd` starts the path, or an explicit directory for a researcher-only
install):

```
modeldir/
  catalog.json
  store/                 4 MiB pieces + piece-index
  tls/cert.pem key.pem   ML-DSA-44, not a wallet
  modeld.sock
```

Never put the catalog in `wallets/` or `chainstate/`.

## Local execution after acquire

After `BYTES_VERIFIED` / `PINNED`, the operator registers the verified path
with a **locally installed** runtime (llama.cpp, a vendor toolkit, etc.).
That runtime is out of band. BTX does not ship a remote inference API.
