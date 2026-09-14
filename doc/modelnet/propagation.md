# Propagation — demand default, bounded preserve-rare

v1.1 **D11**. Payload storage stays **0** until the operator allocates a
budget. That is the DoS bound: BTX MUST NOT autonomously retrieve arbitrary
advertised models.

Once a user **intentionally** retrieves or imports a qualified
redistributable public model, the default policy **retains and
re-advertises** it inside that budget. Nodes MAY additionally fetch
qualified under-replicated resources only when preserve-rare is on.

This is not IPFS “addressable therefore everywhere”. Somebody has to
retain a replica. BTX combines real demand, automatic reseeding, observed
rarity, local budgets, and native money when voluntary supply is not enough.

## Behaviors

```
download / import M
    → verify chunks
    → retain according to local storage budget
    → automatically advertise what you have     (seed=auto)
    → serve it to other peers
    → network gains another replica
```

| Kind | Trigger | Default |
|---|---|---|
| **Demand** | Intentional `importmodel` / `getmodel` | On when storage > 0 and `-modelseed=auto` |
| **Preservation** | Spare quota + observed sources ≤ 2 | Off on CLI; GUI first-run SHOULD check the box |
| **Release** | Local decrypt of a qualified public artifact after key reveal | Demand-seed the **plaintext** identity |

## Flags (`btx-modeld`)

| Flag | Default | Meaning |
|---|---|---|
| `-modelstorage=` / `-modelcache=` | `0` | Quota in bytes or `80GiB`. Zero: no payload, no seed, no preserve-rare |
| `-modelseed=auto\|manual\|off` | `auto` | Auto = seed on intentional download. `manual` = only `seedmodel`. `off` = never auto-advertise |
| `-modelseedupondownload=0\|1` | B0 alias | `1` → auto, `0` → off. **Not** a second opt-in; ignored when `-modelseed` is set |
| `-modelpreserverare` | off | Unsolicited fetch of under-replicated **qualified** public models into spare space. At most one job per minute |
| `-modeluploadlimit=` | 0 | Serving cap (bytes/s). 0 = existing connection ceilings only |
| `-modelallowencrypted` | off | Permit preserve-rare of `ENCRYPTED_UNQUALIFIED` ciphertext |

`getmodelpolicy` / `setmodelpolicy` expose the same fields. `auto_pay` and
non-zero automatic spend remain refused.

`getmodelnetworkinfo.propagation` reports `demand_propagation`,
`preservation_propagation`, `release_propagation`.

## What is served on PQ1

`/availability`, `/query`, `/manifests/{id}` and piece GET serve **seeded**
artifacts only. A local-only download (`-modelseed=off`) is not advertised.
`listmodels` over unix RPC still shows local unseeded entries to the operator.

## Eviction

When the working budget is exceeded, unpinned **common** replicas (many
observed sources) go first. Rare seeded copies rank higher. Pinned copies
are never deleted by this path.

## GUI copy (first-run) — out of scope

Addendum §2.3 recommends this first-run copy. Qt pages are **out of
scope** in this tree; set the same fields with CLI flags above.

```
Model Network Storage
Use up to:                       [ 500 GB ]
Help preserve downloaded models: [✓]
Help preserve rare models:       [✓]
Upload bandwidth:                 [ 20 MB/s ]
Only while idle:                  [✓]
```
