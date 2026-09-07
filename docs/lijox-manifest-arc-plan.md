# MANIFEST ARC PLAN (S35 addendum) — Lanes A+B, big-agenda item 2
Foundation documents, both read in full this session:
lijox-session1-handoff.md (RATIFIED schema + conformance + market
thesis) · lijox-interface-v0.md (DRAFT wallet UX awaiting DP
ratification since S31). This plan does not reinvent either — it
surfaces them, amends them for the package era, and adds DP's new
requirement: a simple "put your sats to work in channels" flow.

## §1 WHAT ALREADY STANDS (ratified, unchanged)
- Manifest tradeoffs schema v0: products[] with rail_class ·
  custody · account · data_collected/retention · revocable +
  revocation_effect · trust_window · unilateral_exit · payer_sees ·
  fee_disclosure. manifest_version + supersedes chain. BIP-340
  signed; key doubles as Nostr npub; CC0 spec / MIT reference code.
- Conformance L1 Honest Reader / L2 Open Market / L3 Sovereign —
  LiJ ships all three as the FIRST L3 wallet, not the special one.
- Market layer (the four standing primitives per interface §1
  TRADE): RFQ · portable receipts · provider panel · interval
  clearing. Sequencing from the handoff stands: RFQ first.

## §2 AWAITING RATIFICATION (interface-v0's own gate, D1–D6)
D1 naming (Shelf/Label/Posture vs plain "Providers") · D2 posture
names (Kept/Open/Sovereign) · D3 verify locus (engine
verify_bip340 export — recommended; sign_message precedent at
lib.rs:1790) · D4 the Zeus-free §0 mandate · D5 bootstrap Shelf
copy ("1 provider listed — the market is young") · D6 menu wording
("Provider").

## §3 S35 PACKAGE-ERA AMENDMENTS (new decisions, Dm-series)
The interface doc predates the Separate Adapter. Its build-order
step 1 ("Adapter v0.37 … ops/adapter patcher + DP hand-load") is
SUPERSEDED: the manifest endpoint ships as lijox-adapter 0.55.0 —
a release EVERY provider gets, which is exactly the Lane A+B
convergence: the package makes any operator listable; the wallet
makes any listing shoppable.

Dm1 SIGNING KEY (the one real new design question): the manifest
    is BIP-340 signed — by WHAT key on the provider box?
    (a) Node identity key via LND signer RPC — binds perfectly but
        widens the least-privilege macaroon (signer scope) and
        drags LND into every manifest edit.
    (b) DEDICATED manifest key, generated at adapter first-run
        (npub-native, rotates independently, macaroon untouched)
        + a ONE-TIME delegation: the operator runs a single
        lncli signmessage over the manifest pubkey and pastes the
        result into config — the node key certifies the manifest
        key, wallets verify the chain (node_pubkey ⇒ manifest_key
        ⇒ manifest). RECOMMEND (b): binding without scope creep;
        the delegation cert rides inside the manifest.
Dm2 SERVING PATH: GET /lijox/manifest (per interface-v0) — public,
    unauthenticated, cache-friendly. Nostr publication is a LATER
    lane (event kind still an open question); v1 ingestion is
    URL-first exactly as interface-v0 planned.
Dm3 SCHEMA ADDITIONS earned since July (all provider-fact fields):
    backup_endpoint (leg-2 per-provider hosting — DP's model) ·
    watchtower block placeholder (the cross-LSP standard note) ·
    reserve_policy { wallet_reserve_sats } (the O3 knob value
    becomes an advertised, comparable fact — a provider demanding
    1% vs 354 sats is now a shopping criterion) ·
    commitment/recovery facts { commitment_type, terminus_pin }
    (seed-only recovery truth as a market differentiator) ·
    registry_free: providers valid with zero registries (Q3).
Dm4 MULTI-LSP ENGINE SCOPE for this arc: v1 = bind/switch with
    channels persisting (LDK is already multi-peer; the wallet's
    single-endpoint CONFIG becomes a provider list with one ACTIVE
    binding). The Sovereign PANEL (striping, MPP-across-panel)
    stays the later phase exactly as interface-v0 postures it.

## §4 NEW REQUIREMENT (DP, this boot): PUT SATS TO WORK — the FUND
action. Interface-v0 covers reading, choosing, and RFQ-buying
inbound; it lacks the OUTBOUND move: funding a channel from the
user's own onchain sats. Amendment:
- A "Fund a channel" action on the Bound view and on Shelf rows
  (house grammar, 2px chamfer), gated on onchain balance > dust +
  fees.
- Flow: pick provider (or the bound one) → amount (with min/max
  from the manifest's channel_limits) → feerate (existing house
  picker) → CONFIRMATION = the O4 OPEN RECEIPT, verbatim: "You are
  sending X: mining fee A + channel capacity B; of B: spendable +
  LiJ Wallet Honesty Reserve + closing-fee carve-out (floats until
  close)." → open_channel_to_lsp (engine, node.rs:3146 — already
  built) → pending card until channel_ready.
- This is the marketplace's demand-side primitive in one tap, and
  it makes O4 land INSIDE this arc rather than after it.
- Honest note rendered in-flow: funding a channel makes YOU the
  funder — the closing-fee carve-out is yours; a JIT channel's is
  the provider's. The manifest's tradeoffs block for the funded
  product states it.

## §5 BUILD ORDER (post-ratification, one step at a time)
0. DP ratifies: D1–D6 (amend freely) + Dm1–Dm4 + the §4 FUND flow.
1. lijox-adapter 0.55.0: GET /lijox/manifest — manifest builder
   from config + Dm3 fields, Dm1(b) key generation + delegation-
   cert verification path, served signed. FINGERPRINT.md updated
   (the manifest is deliberate public surface). UM890 adopts with
   the post-comfort-week batch: the first real listed provider.
2. Engine: verify_bip340 export (+ delegation-chain verify) —
   atomic engine+page commit, buster ritual.
3. Wallet L1: Bound view + the Label + consent record against the
   live UM890 manifest.
4. Consent-diff (supersedes chain) + revocation display.
5. §4 FUND flow (open receipt = O4).
6. LIJOX: URI branch (reference mode) + add-provider by URL.
7. Shelf v1 (URL-added + defaults; Nostr later) + bootstrap copy.
8. Posture control; RFQ v0 rides after per the standing sequence.

## §6 WHAT THIS ARC DOES NOT DO (scope fences)
No Nostr relay work (event kind unresolved — carried open). No
registry product (none exists — Q3 stands). No panel/striping
(Sovereign later). No P1 scoped-token change yet (coordinated arc;
the manifest SCHEMA reserves the field shape, the registry flow
change waits). Whitepaper assembly begins the moment §5 step 3
renders a real Label — the screenshots ARE §4 of the whitepaper.

## §7 THE TWO OBJECTIVES (DP, S35 addendum — the arc's north stars)
OBJ-1 PRIMARY + SECONDARIES (DP vocabulary, ADOPTED into Dm4): a
  primary LSP must exist at all times because wallet FUNCTIONS
  (JIT, holds, wake push, trampoline, chain bridge, rates, quorum
  defaults) are services of one provider, not properties of
  channels; secondaries are channel/capacity relationships only;
  switching primary = rebind. Lower priority by DP ruling; this
  arc builds its foundation (manifest, Label, bind/switch, Fund)
  without the full rewiring.
OBJ-2 SATS THAT EARN (DP): every user able to put sats to work and
  earn. HONEST COLLISION recorded: forwarding income requires
  (a) reversing the locked non-routing invariant and (b) uptime a
  browser wallet constitutionally lacks — an asleep router fails
  forwards, earns dust, and damages payment reliability. THE
  HONEST LADDER: wallet tier = the §4 FUND flow, yield rendered as
  savings/capability (no JIT fees, cheaper sends, capacity,
  privacy) on the envisioned balances/earnings dashboard; earn
  tier = graduate to a provider box — the lijox-adapter (and the
  backlog home-LSP appliance as its consumer packaging): phones
  spend, boxes earn. Wallet↔wallet and third-party channels remain
  possible via Fund as direct-payment lanes, not yield. Dual-
  funded opens (icebox) is where any sleep-compatible capital-
  participation design would live IF one exists without custody or
  uptime — none found; stated plainly. DP ruling: linked, heavy
  rewiring, DO NOT RUSH — banked, not scoped into v1.
- WALLET DASHBOARD VISION noted (distinct from item-3 ops
  dashboard): graphical where-balances-live + what-they-earn/save
  view; rides OBJ work, not this arc's v1.
