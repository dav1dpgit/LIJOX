# LIJOX STANDARD NOTE — CROSS-LSP WATCHTOWER REQUIREMENT (S35, DP proposal)

## The proposal (DP, verbatim intent)
Each LSP on the LIJOX standard must also have enacted a watchtower
available for any LIJOX-class wallets to access and utilize, CROSS
LSP.

## Why "cross LSP" is the load-bearing phrase (first principles)
A watchtower's job is to punish a counterparty that broadcasts a
revoked commitment while you sleep. For a LiJ wallet — a browser,
mostly asleep, with private channels — the counterparty with the
means and the state to attempt that IS THE LSP. A tower run by your
own channel counterparty is therefore worthless against the only
realistic attacker: the fox guarding the henhouse. DP's cross-LSP
framing dissolves the circularity: provider A's tower guards the
wallet's channels WITH provider B (and vice versa). Providers police
each other. Combined with the multi-LSP wallet (S35 invariant:
pluralization both ways), every wallet naturally holds relationships
with ≥2 providers — so every channel can have a disinterested
guardian. This completes the §1 tagline mechanically: "honest by
construction."

## Standard placement (proposed)
- MANIFEST: new field block `watchtower { endpoint, protocol,
  policy (altruist|bonded), max_blobs_per_wallet, retention }` —
  wallets compare towers like they compare fees.
- CONFORMANCE: REQUIRED at full provider conformance; a provider
  without a public cross-wallet tower advertises a lower level and
  the market prices it. (Mirrors the wallet-side L1/L2/L3 pattern.)
- BINDING RULE (wallet side): a conformant multi-LSP wallet SHOULD
  register justice data for channels with provider A at towers of
  at least one provider ≠ A. Never only at A's own tower.

## Technical path (honest about the work)
- ADAPTER SIDE: LND ships an altruist watchtower (wtserver) and the
  tower wire protocol; the adapter can expose/front it as a module —
  session auth can ride the existing signed-challenge scheme, with
  per-wallet blob quotas. Fits the adapter as a config-gated module
  (post-v1; adapter v1 scope stands unchanged).
- WALLET SIDE (the real work): LiJ is LDK/WASM. Justice-blob
  construction from ChannelMonitor revocation data is feasible but
  is engine work, and blob upload must ride each commitment update —
  which fits LiJ's life pattern: the wallet is BY DEFINITION awake
  exactly when state changes (it's the one transacting), so tower
  updates piggyback on payment liveness. No background requirement.
- PRIVACY: tower protocol stores encrypted blobs keyed by txid
  hint — the tower learns nothing about the wallet until an actual
  breach tx appears. Fits doctrine as-is.
- OPEN QUESTIONS (banked, not blocking): wire choice (adopt LND's
  tower protocol as v1 wire vs define a LIJOX tower API over HTTPS);
  anchors/STATIC_REMOTE_KEY interactions with justice construction;
  bonded/reward towers as a later market layer; blob quota economics.

## Terminology ruling this session (wallet copy v534)
LDK ChannelMonitors are NOT watchtowers — they are the wallet's own
on-device record keepers, active only while the wallet runs. The
Balance drilldown MONITORS bubble now says exactly that, reserving
the word "watchtower" for the real thing this note proposes.
