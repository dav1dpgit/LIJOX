# LIJOX ADAPTER — PRODUCT DEFINITION (S35, design before code)
Written on DP's instruction to define the thing before building it.
This document says WHAT the shareable adapter is; the discovery doc
(separate-adapter-discovery.md) says what today's code does; the gap
between them is the work plan.

## §1 DEFINITION (DP-ratified wording, S35)
LiJ wallets are self-sovereign, multi-LSP-agnostic wallets built on
the LIJOX standard. The LIJOX standard is the open tooling that
separates wallets from operators' services — no wallet is captive to
any provider. A LIJOX Adapter is open-source, self-hosted software
that translates an operator's existing Lightning services into a
LIJOX-standard LSP for LiJ-class wallets — JIT channels, offline
holds, wake push, and the LIJOX manifest — under the operator's own
keys, own front door, own policies, and own registry choices.
Download, configure, serve. No permission asked, no secrets shared,
no home to phone.
  A standard LSP serves wallets that are apps; a LIJOX Adapter lets
an operator serve wallets that are browsers, mostly asleep, and free
to leave — and makes that operator comparable, swappable, and honest
by construction. Nearly everything distinctive in this adapter
exists because LiJ wallets are browsers, usually asleep, and
constitutionally distrustful — the WS⇄TCP front door (browsers
can't open raw TCP; without it a browser wallet can't exist at
all), the offline-first receive stack (holds + MPP aggregation +
wake push + trampoline settle, where standard LSPS2 just fails an
offline recipient), client-set policy (the wallet dials the LSP's
behavior, not only vice versa), the seed-only recovery registry
(nothing but 12 words rediscovers your channels — no LSP offers
this), attempt-journal forensics, privacy proxies, the signed
manifest that makes operators comparable and swappable, and
non-routing leaf accommodation.

## §2 WHO RUNS IT (the participant DP described)
A LIJOX-standard participant running their own LSP of some form:
- Has: an always-on box, an LND node with capital, the intent to
  sell inbound liquidity + LSP services to sovereign wallets.
- Is not: a custodian of wallet funds (channel counterparty only),
  a Plotzwerks affiliate, or anyone needing DP's approval. LIJOX is
  OPEN — permissionless enrollment, market discipline only.
- Skill floor: can run a systemd service and edit a config file.
  The first-run doctor carries them the rest of the way.

## §3 WHAT IT DOES (capability map, from the route inventory)
CORE — the LSPS2 service (always on):
  get_info / buy / pending · HTLC-interceptor JIT opens · offline
  holds + MPP shard aggregation · trampoline settle via
  register_secret · WS⇄TCP P2P tunnel front (:7001) · /health ·
  /quorum/defaults · /client/prefs · /attempts · admin surface.
LIJOX LAYER (what makes it a *LIJOX* provider):
  Serves the signed provider manifest (per the Manifest & Binding
  Standard, CC0 spec) · enrolls in ZERO OR MORE registries of the
  operator's choosing (see Q3) · channel-record registry service for
  seed-only wallet recovery (signed-challenge auth).
  FUTURE (standard proposal S35, see lijox-watchtower-note.md):
  cross-LSP watchtower module — each provider offers tower service
  to any LIJOX wallet, guarding channels held with OTHER providers;
  required at full conformance. Post-v1 for this package.
OPTIONAL MODULES (config-gated, each OFF unless enabled — see Q2):
  LNURLp / lightning address service · delegate payment rail (Page)
  · lease (connection-based channel expiry) · rates proxy (wallet
  IPs never touch tickers) · web-push wake notifications (VAPID
  generated locally) · open-intent · cooperative chain bridge ·
  tapedrop (flight-recorder intake — a DEBUG pipe; see Q2 privacy
  note).

## §4 WHAT IT IS NOT (non-goals, v1)
- Not a wallet, not custody, not a Lightning implementation.
- Not a routing-node manager or fee optimizer.
- Not multi-tenant (one operator, one node, one config).
- No web admin UI — the minimal ops dashboard is the NEXT roadmap
  arc and will consume this package's admin API; the adapter ships
  headless with journald + admin routes.
- Not an abstraction over every node implementation (see Q1).

## §5 POSTURE (the non-negotiables, from DP's charge + §7 P1–P8)
- Operator sovereignty: runs against THEIR node with THEIR keys.
  Every secret is generated on the operator's box (openssl recipes,
  macaroon bakery). Nothing pre-baked, nothing shared.
- No phone-home: no telemetry to Plotzwerks, no forced registry,
  no update beacon. Registry enrollment is explicit config.
- Scoped credentials: least-privilege macaroon recipe (D3); the
  registry receives a scoped route token, never the admin secret
  (P1 — and a LIJOX-standard change to match).
- Privacy by default: IP-log off-switch, journald bounds in the
  unit, data-at-rest policy in the README, debug intakes off (Q2).
- NO-EXCLUSIVITY INVARIANT (DP, this boot: multi-LSP goes both
  ways — the LiJ wallet is becoming multi-LSP enabled): the adapter
  never assumes it is a wallet's only LSP. No state, policy, or
  flow may treat its channels, prefs, push subs, or journals as the
  wallet's whole world; wallets aggregate providers, providers
  serve non-captive wallets.
- PERFORMANCE PARITY (DP, S35): the packaged adapter must run at
  least as fast as the in-place one. Rule: no new work on the
  per-payment or per-request paths — checks and validation run at
  STARTUP ONLY. Measured at cutover: same-box before/after timing of
  a JIT buy→usable and a plain pay/receive, plus /health/jit
  latency. Any regression blocks cutover.
- Fail loud: required identity config with no defaults (D6) —
  a misconfigured money service should refuse to start, not limp.

## §6 DEFINITION OF DONE (the two-sided test)
A. STRANGER TEST: an operator we have never met takes the lijox-adapter repo,
   and with only its README + doctor goes clone → configured →
   serving a LiJ wallet JIT open, in under an hour, zero DP
   involvement. (This is the Multi-LSP arc's "run one yourself"
   marketing proof.)
B. CUTOVER TEST — ★ PASSED 2026-08-15 (S35): the UM890 retired the
   patched-forward lij-adapter.js and runs lijox-adapter v0.53.1
   under the hardened unit. Doctor full pass in production; timing
   parity nets FASTER (health 6.08→5.80ms avg); real receive FASTER
   than its own baseline; send first-try. DP's box is install #1.
   Patcher freeze (D5) follows the comfort week.

## §7 SCOPE RULINGS NEEDED (sharp questions, DP answers set v1)
Q1 NODE SUPPORT — ★ RULED (DP): LND-only v1 (REST+gRPC as coded;
   ANCHORS on stock lnd, Terminus patch documented optional), BUT
   built as if more backends come later — explicitly including
   non-Lightning-node participants (Ark, Spark). DESIGN CONSEQUENCE:
   the backend boundary is a SERVICE CONTRACT, not an implementation
   switch — document the narrow internal surface the adapter
   actually consumes (invoice create/decode/settle, pay, channel
   list/open, HTLC interception, message sign/verify, chain
   notifications, peer connectivity); LND is the sole v1
   implementation of that contract; no LND types or REST/gRPC
   shapes leak past the boundary; NO speculative driver code.
Q2 MODULE TIERING — ★ RULED (DP: agreed on both): which optional modules ship IN the public
   package v1? Sub-questions with recommendations:
   - delegate rail: couples to Page. Ship config-gated OFF
     (RECOMMEND) or hold for a Page-era release?
   - tapedrop: it is OUR debug evidence pipe; a third-party
     operator collecting wallet flight tapes is a privacy surface.
     RECOMMEND: dev-flag only, excluded from normal config surface.
   - lease: dormant-by-default as today. RECOMMEND: ship.
   - LNURLp, rates, push, open-intent, chain bridge:
     RECOMMEND: ship, each behind its own enable flag.
Q3 REGISTRY STANCE — ★ RULED (DP: agreed; noting his correction
   that no product registry exists yet — the dp-a95 worker is dev
   scaffolding, not a registry product): enrollment optional and
   PLURAL — REGISTRY_URLS accepts a list, EMPTY BY DEFAULT; the
   adapter is fully functional with zero registries.
Q4 NAME — ★ RULED (DP: "LIJOX Adapter"; Claude concurs on the
   merits): the OPERATOR is the provider (human + node + capital);
   the SOFTWARE is the adapter that translates their services into
   the standard — matching the ratified §1 verb. Repo/package:
   lijox-adapter. "Provider" remains the word for the running
   participant, exactly as the LIJOX spec uses it.

## §8 CENSUS DELTAS (R1 read, folded into the transport plan)
New to the map vs the discovery doc: cooperative-chain-msg.js
(+ .test.js) — near-certain dep of chain-bridge, making SIX local
modules not five · lnd-streams.js (May 5 vintage — verify required
before inclusion) · TUNNELS.md (12KB tunnel documentation — pull;
may satisfy R3 without a cloudflared read) · five protos
(lightning, lightning-openchannel, router, chainnotifier,
walletkit) · package.json 450B + package-lock 39KB · registry.db
(+-shm/-wal) present from the May SQLite era (informs D2 —
the backend once ran; the conflict story is testable) ·
lij-adapter-v2.macaroon loose in the dir (cutover hygiene item;
also chmod 640→600 class) · ~100 .bak/backup files: never travel.
PULL LIST (post-definition, post-scan): lnd-grpc.js, registry.js,
registry.test.js, cooperative-chain-bridge.js,
cooperative-chain-msg.js, cooperative-chain-msg.test.js,
(lnd-streams.js if required), 5 protos, package.json,
package-lock.json, TUNNELS.md. Everything else stays home.

## §9 WHAT A LIJOX ADAPTER ADDS BEYOND A STANDARD LSP (DP's aside,
answered from the route/code inventory — this list is whitepaper
raw material)
A standard LSP (the LSPS0/1/2 world) sells channels to ONLINE,
NATIVE-APP wallets that speak raw TCP and typically live with one
LSP. Nearly everything distinctive below exists because LiJ wallets
are BROWSERS, usually ASLEEP, and constitutionally DISTRUSTFUL:
 1. BROWSER FRONT DOOR: the WS⇄TCP tunnel lets a PWA speak
    Lightning P2P at all (browsers cannot open raw TCP). Almost no
    LSP offers this; without it a browser wallet cannot exist.
 2. OFFLINE-FIRST RECEIVE STACK: bounded HTLC holds for sleeping
    wallets + MPP shard aggregation window + wake push (VAPID) +
    reconnect-poll/resume grace + trampoline settle via
    register_secret. Standard LSPS2 simply fails when the
    recipient is offline.
 3. CLIENT-SET POLICY: the wallet dials LSP behavior
    (/client/prefs hold ceiling; the reserve-dial philosophy) —
    the user configures the provider, not only vice versa.
 4. SEED-ONLY RECOVERY REGISTRY: signed-challenge channel-record
    store so a wallet with nothing but its 12 words rediscovers
    its channels. Not a standard LSP service anywhere.
 5. ATTEMPT JOURNAL: hash-scoped payment forensics the wallet can
    query — an honesty/observability surface.
 6. PRIVACY PROXIES: rates proxy (wallet IPs never touch tickers)
    + LSP-declared quorum endpoint defaults the wallet verifies
    against + one-at-a-time broadcast routing support.
 7. MANIFEST + CONFORMANCE: signed, machine-readable terms (fees,
    hold ceiling, trust window, unilateral exit, conformance
    level, intro offers) so wallets COMPARE and SWITCH providers —
    the open-market piece; standard LSPs are discovered by
    hardcoding.
 8. NON-ROUTING LEAF ACCOMMODATION: private channels, no gossip,
    forward attempts rejected — the JIT/trampoline design assumes
    sovereign leaf wallets.
 9. LEASE TRANSPARENCY: declared connection-based channel-expiry
    policy, wallet-readable.
10. OPTIONAL RAILS beyond any LSP: delegate payment instruments
    (chits) and hosted LNURLp/lightning addresses with honest
    min/max from real channel state.
THE ONE-LINER: a standard LSP serves wallets that are apps; a
LIJOX Adapter lets an operator serve wallets that are browsers,
mostly asleep, and free to leave — and makes that operator
comparable, swappable, and honest by construction.
