# LIJOX Interface in LiJ — Definition v0

STATUS: DRAFT for DP ratification (S31, 2026-07-30). Definition
only — nothing here builds until DP says go. Deliverable class:
spec text; the byte-exact patch ritual begins when reference code
begins.

Working vocabulary (naming itself is decision D1): the LABEL (the
verbatim disclosure surface), the SHELF (discovery + comparison),
the POSTURE (the complexity/privacy slider). House metaphor: every
provider is a jar on a shelf; every jar carries a label. Plain
"Providers" stays the fallback if DP prefers no metaphor.

## 0. Mandate, restated (Zeus removed — DP ruling S31)

LIJOX exists so that any conforming wallet gives its holder four
things no bundled wallet offers: discovery without gatekeepers,
terms signed before commitment, trust labeled honestly wherever
funds rest, and exit that is free. The market layer — quotes,
portability, diversification, clearing — can only exist between
providers, and only a standard can stand between providers. LiJ is
the first venue member, not the definition. Other wallets are
specimens and case studies, never benchmarks: the standard is
measured against what a holder gets, not against any competitor's
feature list.

## 1. What it is

The LIJOX interface is the surface inside LiJ where the provider
relationship stops being invisible plumbing and becomes an object
the user can read, compare, change, and eventually put out to bid.
Four verbs, mapped to the conformance levels LiJ intends to ship:

- READ (L1). The bound provider's signed manifest rendered
  verbatim — the Label. Signature verified before display;
  unsigned or mismatched renders as untrusted, never silently
  accepted. Any worsening revision produces a diff and blocks
  liquidity actions until re-consent.
- CHOOSE (L2). The Shelf — listings aggregated from ≥2 independent
  registries, union by pubkey, side-by-side tradeoffs, activation
  by LIJOX: URI. Switching is a profile swap: existing channels
  persist and the old provider remains an ordinary peer. No
  un-consented default, ever.
- HOLD HONESTLY (L3). Balances segmented by rail_class and
  unilateral_exit — LiJ is single-rail today, so the frame ships
  trivially satisfied, and a future rail can never blend into
  "your money" unlabeled. Zero-conf provisional display,
  close-awareness states, revocation_effect shown before
  execution, Terminus recovery unchanged beneath it all.
- TRADE (§9 as amended). At a liquidity event, RFQ across listed
  or paneled providers; signed quotes; execute best by rule or by
  tap. The four standing primitives — RFQ, portable receipts,
  provider panel, interval clearing — all enter the wallet through
  this one surface.

This interface is LiJ's claim to first-L3-wallet, and it is the
demand side of the LIJOX market bootstrapping itself: the first
venue member's storefront.

## 2. How it looks

Placement: one hamburger entry ("Provider" — wording is D6)
opening the bound view; plus two contextual surfacings that are
not menu screens — the consent interstitial (first bind, rebind,
worsening diff) and the RFQ sheet (liquidity events, Open posture
and above).

Surfaces:

1. BOUND VIEW. Identity row: alias in Geist Sans with the pubkey
   fingerprint in Geist Mono directly beneath — fingerprint-first
   per design-22 M3 (alias is decoration, pubkey is identity) —
   plus a first_seen age chip. Signature badge: verified in amber
   (#e8a23a) / untrusted in warn (#b8593a). Live RTT dot rides the
   existing _lijLspRttMs machinery. Products list: one card per
   products[] entry with headline chips (rail_class · custody ·
   trust_window · fee). Actions in the house grammar (2px
   chamfer): View full label · Switch · Revoke.

2. THE LABEL. Specimen-style card on --surface: field names in
   Geist Mono --ink-3, values VERBATIM in --ink, signature line at
   the foot (BIP-340 · npub · manifest_version · supersedes).
   Plain-words captions MAY sit above rows in the copy-bank voice
   (custody: none → "your keys hold the money") but the verbatim
   block is always fully present and primary — captions add, never
   replace, never bury (L1 law). Diff view: changed fields
   highlighted before → after; a worsening diff blocks liquidity
   actions until re-consent.

3. THE SHELF. Rows from the aggregated registry union: alias +
   fingerprint + age + headline chips + a single-source flag when
   only one registry carries a listing (design-22 M4). Sort and
   filter on tradeoffs fields — privacy properties become shopping
   criteria: payer_sees, data_collected ceiling. Compare is two-up
   on mobile. "Add registry" lives under an advanced disclosure.
   While the market is young the Shelf says so plainly: "1
   provider listed — the market is young" (copy is D5) — the
   honest bootstrap exception to L2's ≥2-alternatives rule.

4. CONSENT INTERSTITIAL. Full-screen Label, pre-commitment —
   before the first sat moves or the first invoice wraps. Explicit
   accept writes the consent record.

Palette and geometry are the live styles.css tokens, re-read this
session: --bg #f6f1e7 · --surface #fffdf5 · --ink #26190f ·
--accent cognac #b8895a · --amber #e8a23a · --warn #b8593a · Geist
Sans/Mono · 2px chamfer actions · 8px-radius cards. Nothing new is
invented; the Label inherits the wallet's paper-and-ink language
so disclosure reads as part of the wallet, not a legal popover.

## 3. How it runs and connects

Module law: a new closure section with its OWN bases (LX_ prefix:
LX_REGISTRY_RELAYS, LX_RFQ_TIMEOUT_MS, …) per the module-scope
rule; no cross-scope refs; observable console tag [lijox] so DP
can grep tapes without a console.

Stores (versioned localStorage, lij_last_known_v1 pattern):
- lij_lx_bound_v1 — active binding: manifest snapshot + consent
  record {manifest_version, sig, consented_ms}. The consent record
  is the deterministic diff base for the supersedes chain.
- lij_lx_shelf_v1 — cached listings + fetched_ms + source
  registries per listing.
- lij_lx_posture_v1 — posture + individual privacy overrides.
- lij_lx_panel_v1 — Sovereign panel set (later phase).

Manifest ingestion v0 (before Nostr): the adapter serves
GET /lijox/manifest — LiJ-Node's own signed manifest as static
JSON. UM890 becomes the first real listed provider and the signing
path is exercised end-to-end on day one. The wallet verifies
BIP-340 before render. Verify locus (D3): an engine export
verify_bip340(pubkey_hex, msg, sig_hex) — sign_message already
exists at lij-wasm lib.rs:1790 and the vendored bitcoin stack
carries secp256k1; a small export keeps trust-surface crypto in
the engine and adds no JS dependency. Cost: the first Label build
is an atomic engine+page commit with the buster ritual.
Alternative (vendored noble-secp256k1, frontend-only deploy) is
rejected unless DP overrules — a sovereignty wallet should not
carry a second crypto implementation for its trust surface.

Registry v1: Nostr relay WebSocket subscribe (event kind = carried
open question), aggregate ≥2 relays, union by pubkey, dedupe by
manifest_version, verify every signature, cache to the shelf
store, render single-source flags. Registry metadata exposure is
stated honestly on the privacy screen: relays learn that this IP
asked for LSP listings — never balances, never payments.

Activation URI: lijParseScan gains a LIJOX: branch — reference
mode (URI → fetch manifest → verify → Label → consent → bind) and
inline mode (base64 manifest inside the URI, no fetch). Paste path
included. Cross-app scheme registration (web+lijox
protocol_handlers) is deferred: scanner + paste is the v0 floor,
honest about PWA physics.

Bind / switch / revoke: bind writes the consent record, peers with
the manifest's connection_methods, and adopts declared product
endpoints (LSPS2 base, open_intent endpoint per spec §6.4). Switch
= a new bind; channels untouched; the old provider persists as an
ordinary peer. Revoke shows the declared revocation_effect,
executes, writes a ledger row.

RFQ v0 (posture-gated): POST a quote request {product,
amount_sats, expiry_ms} to each candidate's declared rfq endpoint;
responses are signed quotes with validity windows; the wallet
compares total cost and executes best — automatically in Open with
a receipt line ("best of N quotes"), via a review sheet in
Sovereign. The envelope format is LiJ-defined in v0 and promoted
to the standard after field test: the reference implementation
earns the spec text, exactly as Open-Intent did.

## 4. The slider — postures

One visible control, three postures. The law: COMPLEXITY SLIDES,
HONESTY DOESN'T — L1 verbatim rendering, L3 truthful states,
provisional zero-conf, and re-consent on worsening hold at every
posture. Custody never changes: all three postures are the same
non-custodial wallet.

- KEPT (default). One bound provider; the wallet just works. The
  Label appears at consent moments only. No RFQ UI; the bound
  provider's schedule applies. The Shelf is reachable, not
  surfaced. First bind still shows the Label and any listed
  alternatives — suggestion is allowed, an un-consented default is
  not (L2 law).
- OPEN. The Shelf surfaces; switching is one tap. RFQ runs
  automatically across listed providers at liquidity events,
  executes best, and leaves a receipt line. Still one active
  provider.
- SOVEREIGN. A panel of 2–3 providers with liquidity striped
  across them; MPP across the panel (the machinery exists); manual
  RFQ review; per-provider balance segmentation; registry
  management; raw manifest JSON; Open-Intent visibility.

Privacy is a sub-axis the posture defaults but never owns —
individual toggles override: payer_sees preference (prefer
wrapped-invoice providers), data_collected ceiling filter,
registry relay set + fetch cadence, panel striping (Sovereign: no
single provider sees all flow).

## 5. Build order (post-ratification, one step at a time)

1. Adapter v0.37: GET /lijox/manifest (signed static JSON for
   LiJ-Node) — ops/adapter patcher + DP hand-load ritual.
2. Engine verify_bip340 export + page Provider bound view + Label
   + consent record (atomic commit, buster ritual). L1 complete
   against one real provider.
3. Consent-diff machinery (supersedes chain) + revocation display.
4. LIJOX: branch in lijParseScan (reference mode first).
5. Shelf + Nostr registry read + single-source flags (L2 skeleton
   with the bootstrap-exception copy).
6. Posture control (Kept default; Open unlocks with the Shelf).
7. RFQ v0: adapter endpoint + wallet loop + receipt line.

Field test gates every step; DP device verdicts are ground truth.

## 6. Decision points for DP

- D1 Naming: the Shelf / the Label / the Posture metaphor, or
  plain "Providers" throughout.
- D2 Posture names: Kept / Open / Sovereign.
- D3 Verify locus: engine export (recommended) vs vendored JS lib.
- D4 Ratify the §0 mandate restatement (Zeus-free).
- D5 Bootstrap-exception Shelf copy: "1 provider listed — the
  market is young."
- D6 Menu entry wording: "Provider".

## 7. Open questions carried (unchanged from the LIJOX handoff)

Nostr event kind · L2 ≥2-registry floor bootstrap exception (D5's
honest label partially answers it — confirm) · fee_disclosure
order-based vs flow-based · RFQ anti-gaming (validity windows,
last-look prohibition, firm vs indicative quotes) · receipt
attestation privacy · shadow manifests for undisclosed rails ·
clearing parameters · interactive-tx maturity across
implementations.
