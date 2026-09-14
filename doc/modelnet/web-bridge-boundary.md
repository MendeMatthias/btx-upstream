# Web / browser bridge boundary (optional)

Normative: root addendum §10 (D09). Optional profile; native-only is valid.
Browser / Qt pages are **out of scope**. Not CSV PASS.

v1.1 D09: native model transport remains **strict PQ1**. A browser bridge
is a **separately deployed** compatibility service.

| Edge | Allowed | Claim |
|---|---|---|
| Native `btx-modeld` | PQ1 only (ML-KEM-768, ML-DSA-44, AES-256-GCM-SHA384) | End-to-end PQ for that hop |
| Browser HTTPS | Conventional HTTPS at the **external** browser edge | Explicitly **not** end-to-end PQ |
| Bridge → BTX | Still PQ1 upstream | Never a wallet proxy or payment authority |

A PQ-only deployment **omits** the bridge. D09 is not permission to restore
classical TLS inside `btx-modeld`.

See [howto.md](howto.md) for the public-CA operator kit
(`contrib/modelnet/e2e-public-webpki-kit.sh`). Native `btx-modeld` never
terminates TLS at this edge.
