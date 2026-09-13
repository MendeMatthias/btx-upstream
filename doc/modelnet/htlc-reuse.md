# Model release campaigns reuse 0.34.6 HTLC

0.34.7 does **not** add `htlc_sha256_tx`, `buildmodelhtlcclaim`, or
`buildmodelhtlcrefund`.

Final 0.34.6 already provides:

- `htlc_sha256(<SHA256>, <PQ claimant>)`
- `mr(htlc_sha256(...), refund(height, key))`
- `buildhtlcclaim` / `buildhtlcrefund`
- descriptor alias `model_htlc_sha256` (canonicalizes to `htlc_sha256`)

HASH160 `htlc_tx` remains **recovery-only**. New campaigns MUST use SHA-256
hashlocks (`ReleaseHash` = SHA-256 of a 32-byte secret), never HASH160.

HTLC success proves payment, not model correctness, safety, or usefulness.
Default automatic spend is zero; a paid quote still requires an explicit
budget or approval.
