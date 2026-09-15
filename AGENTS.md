# Agent notes (BTX 0.34.7)

Two planes. Do not mix them.

## Monetary plane

`btxd`, consensus, wallet, ExactReplay.

Search, feed, and campaign popularity **must not** affect block validity,
fork choice, difficulty, issuance, miner preference, or monetary peer scoring.

## Model plane

`btx-modeld`: discovery, search, transfer, release **coordination**.

- Never put search/feed state in consensus.
- Never let modeld hold wallet secrets.
- No remote inference.
- `automatic_spend_atoms` is 0.
- Strict PQ1.
- Release finance reuses SHA-256 HTLC (`htlc_sha256`), not HASH160.
- Peer/provider counts are observations, not global truth.

## Key APIs (schema 3 economy/feed)

`searchmodels`, `getmodeleconomyentry`, `getmodelfeed`,
`getmodelfeedstatus`, `getfundablemodels`, `getmodelreleaseeconomics`,
`getrecentlyunlockedmodels`, `preparefundmodelrelease`.

Lifecycle labels (`PUBLIC`, `FUNDING`, `FUNDED_AWAITING_RELEASE`,
`SECRET_DISCLOSED`, `PUBLIC_RELEASED`, …) are not consensus.

`pledged` ≠ `funded`. If confirmed chain funding is unknown,
`value_known=false` — do not invent percents.

New search records sign `BTX/ModelSearchRecord/v2`. Do not treat v1
signatures as covering tags/languages/release terms.

`CLIENT_VERSION_IS_RELEASE` stays false until every mandatory 0.34.7 gate
has executed evidence.
