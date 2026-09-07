# Open-Intent v1 — Resumable Wallet-Funded Channel Opens
**Status: DRAFT (DP-ratified direction, 29 Jul 2026). LIJOX optional extension.
Trustless Mode B only — no LSP custody of client funds at any point.**

## 1. Problem
A wallet-initiated, wallet-funded channel open is a strict multi-message
handshake (open_channel → accept_channel → funding_created → funding_signed
→ broadcast → confirm) that LDK discards the instant the peer connection
drops. Mobile sessions are short and churny; the handshake often cannot fit
inside one session. Industry practice (Phoenix, Breez, Bitkit, LSPS1)
solves this by flipping the initiator to the always-on LSP — at the cost of
a custodial payment window (LSPS1) or total single-LSP dependency. Open-
Intent keeps the WALLET as the funder (trustless end-to-end) and makes the
INTENT the durable object; each handshake is a disposable attempt.

## 2. Roles & trust
- Client: funds the channel from its own on-chain coins. Never pays the
  LSP anything for the open itself (JIT/LSPS2 fees are out of scope here).
- LSP: accepts inbound opens per its normal policy; additionally stores
  intents and reports status. The LSP can never take client funds under
  this protocol — worst case is a failed open, already protected by the
  client's funding-spent gates and unilateral sweep path.
- Auth: every client message is BIP-340-signed by the client node key
  (lij: `sign_message` export). LSPs MUST verify.

## 3. Objects
### 3.1 Intent (canonical JSON, client-signed)
```
{
  "v": 1,
  "intent_id": "<uuidv4>",
  "client_pubkey": "<33B hex>",
  "amount_sats": <u64>,
  "fee_rate_sat_vb": <f32>,          // client's funding feerate at creation
  "created_ms": <u64>,
  "expiry_ms": <u64>,                // client-chosen; RECOMMENDED 24h
  "sig": "<BIP-340 over the canonical string of all fields above>"
}
```
Idempotent by `intent_id`. Re-POST with same id = no-op, returns state.

### 3.2 State ladder (LSP-reported, observation-derived)
```
RECEIVED        intent stored, nothing observed yet
NEGOTIATING     LSP node shows a pending channel matching
                (client_pubkey, capacity == amount_sats)
FUNDING_SEEN    funding txid observed (mempool or blocks)
CONFIRMED       channel active on the LSP node
EXPIRED         expiry_ms passed with no CONFIRMED
```
The LSP derives states purely from its own node (pendingchannels /
listchannels / chain view) — no message sniffing, no client trust.

## 4. Transport (HTTPS, the reliable rail)
- `POST /openintent`   body = Intent. 200 {ok, state} | 4xx {ok:false,code}
- `GET  /openintent/<intent_id>` → {ok, state, funding_txid?, attempts_seen?,
   expiry_ms}
LSPs MAY also expose these over LSPS0 JSON-RPC; HTTPS is the v1 floor.

## 5. Client re-drive loop (the compensation)
Persist the intent locally at creation (survives reloads). Then, while
state ∉ {FUNDING_SEEN, CONFIRMED, EXPIRED} and attempts < MAX (5):
1. Wait for peer liveness (the one-oracle rule: the LN socket, not a
   registry) after each (re)connect.
2. Re-drive: call the normal open (create_channel path) with the SAME
   amount + feerate; run the outbound pump burst (v197/v423) through the
   handshake window.
3. On LDK discarding an attempt (ChannelClosed, unfunded class): that is
   an ATTEMPT failure, not intent death — loop continues next liveness.
4. On any attempt reaching funding broadcast: stop re-driving; the
   existing rebroadcast-until-seen + Step-3 janitor own the rest.
Client UI states: "opening — attempt N of 5 · waiting for connection /
retrying / broadcasting / confirming". EXPIRED or MAX ⇒ honest final row.
Safety: the funding-spent gate + chain-freshness gate run before EVERY
attempt (no attempt can double-spend a prior attempt's inputs).

## 6. LSP obligations (mimicable minimum)
1. Store intents (idempotent), verify sig, enforce expiry.
2. Serve GET status derived from own-node observation (§3.2).
3. Acceptor patience: MUST NOT penalize repeated inbound opens from a
   pubkey holding a live intent (maxpending headroom permitting).
4. MAY advertise support in a LIJOX manifest capability:
   `"open_intent": {"v":1, "max_expiry_ms":..., "endpoint":"/openintent"}`.
Nothing here requires LDK, LND specifics, or lij code — any LSP stack can
implement §6 in an afternoon.

## 7. Why this beats the compromised positions
Phoenix-class: robust but sole-LSP custodial-adjacent dependency. LSPS1
Mode A: robust but a custodial payment window. Open-Intent: the client's
coins never leave the client's control, the LSP is replaceable (LIJOX-
open), and robustness comes from durability + retry, not from surrender
of the funding role.

## 8. v1 build order (lij reference implementation)
1. Adapter v0.35: the two endpoints + intent store + observation mapper.
2. Frontend: intent persistence + re-drive loop + attempt-aware pending
   row (extends lijOpenPending / the v418 synthetic row).
3. Engine: none required for v1 (sign_message, open path, pump all exist).
4. Field ritual: open on LTE, deliberately background mid-handshake,
   watch attempt 2 land after reconnect.
