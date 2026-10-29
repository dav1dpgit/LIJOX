# LIJOX — the channel backup (round 1, 2026-10-29)

Status: round 1, written on DP's word (2026-10-29 12:22: "Yes go ahead on all notes and ready to publish"). It writes
down, as a standard, what Session 22 ratified in July — "the encrypted backup is STANDARDIZED — blob format, seed-based
derivation, challenge auth, and endpoint discovery — so ANY LIJOX wallet opens the blob and lets the user reestablish
or close the channels" — and adds DP's rulings of 2026-10-29. Sections 1–4 describe what is built and running today
(engine v359, registry worker 0.18.0), from the code. Sections 5–8 are the standard's next steps; nothing in them is
built yet.

DP, 2026-10-29: "the wallet user, being separate from the LSP, can discard an old wallet and choose a different-issued
wallet from another company or make their own, and as long as it adheres to the LIJOX standard, said user can choose
the same LSP and use the same channels, without closing them, with the channel backup/recovery." — "It should be as
versatile as the Adapter." — on an engine-neutral channel-state format and engines willing to import it: "This is our
objective, and it starts as a spec paragraph." — on VSS as a server underneath: "Agreed, add it to the spec."

## 0. Words used here

- **The 12 words** — the wallet's key (BIP-39). Everything in this document is derived from them.
- **The channel backup** — a sealed copy of the wallet's full channel state. With the 12 words it brings a wallet back
  with its channels OPEN: the same channels, with the same provider, carrying on. Kept online ("the cloud copy") and,
  when the user saves one, as a file on the phone ("the device file"). Both hold the same sealed bytes.
- **The Black start kit** — a different thing (docs/black-start-standard.md in the wallet's repo): signed transactions
  that CLOSE every channel without anyone's help. It is the fallback when no channel backup can be found.
- **A backup server** — any server that stores channel backups under the API in §4.
- **The password** — the wallet's own password on the phone. It seals the 12 words on that phone only. It plays no
  part in the channel backup.

## 1. Keys from the 12 words

- `seed` = the BIP-39 seed of the 12 words with an empty BIP-39 passphrase.
- `master` = the BIP-32 master private key of `seed` (the left 32 bytes of HMAC-SHA512(key = "Bitcoin seed", seed)).
- **The seal key** `S` = HKDF-SHA256(ikm = `master`, salt = `"lij-persist-v1"`, info = `"ChannelMonitor"`), 32 bytes.
  Used for AES-256-GCM only.
- **The backup identity** = the BIP-32 key at `m/525h`. Its 33-byte compressed public key (`pubkey_hex`) names the
  backup at every server; its private key signs every request to a server (§4). Nothing about the public key is
  secret.

The seal key and the Black start kit's key are different HKDFs of the same master key, so a holder of one can never
open the other.

## 2. The envelope (what a server stores — readable by the server, except the sealed part)

```
{ "version":        <whole number, ≥ 0 — rises by at least 1 with every new copy>,
  "encrypted_data": [ <bytes 0–255> … ],     // the sealed part, below
  "nonce":          [],                      // always empty today — the nonce travels inside encrypted_data
  "pubkey_hex":     "<33-byte compressed public key of m/525h, hex>",
  "saved_at_ms":    <unix milliseconds when the copy was taken; 0 = an older engine that did not record it> }
```

- `encrypted_data` = `nonce (12 random bytes) ‖ AES-256-GCM(S, nonce, plaintext)` (the 16-byte tag at the end; no
  associated data).
- **The fingerprint** of a copy = SHA-256 over the `encrypted_data` bytes, as hex. It tells two copies apart without
  opening them.
- A copy with a higher `version` replaces a lower one. Copies are never merged.

## 3. The sealed part (what only the 12 words can open)

Today the plaintext is one JSON object: storage key → hex of the stored bytes. It holds:

- `lij:channel_manager` and every `lij:monitor:<…>` — LDK's own channel records (`ChannelManager`, `ChannelMonitor`s),
  serialized by LDK 0.2;
- the output sweeper's state (keys under its prefix) — sweeps in flight after a channel closes;
- the on-chain wallet's view, pending sends and coin marks; the channel-index counters; the static-address (LNURL)
  preimage pool and index; Push Keys sent and received; NWC connections; the closed-channel log; the Mix's unsettled
  records.

The channel records are LDK's format. **So today another wallet can continue these channels only if it is built on
LDK and reads LDK 0.2 records.** That is the honest limit of round 1; §5 and §8 are how the standard removes it.

## 4. The backup server API (the reference server: `lij-worker`, LIJOX repo, 0.18.0)

Every request is proved by the backup identity — no account, no shared secret.

1. `GET /backup/challenge?pubkey=<pubkey_hex>` → `{ nonce: <64 hex>, expires_in: 120 }`. One use; two minutes.
2. The wallet signs a digest with the `m/525h` private key — compact secp256k1 ECDSA, 64 bytes (r‖s), sent as 128 hex:
   - to read or delete: `sha256("lij-backup-v1" ‖ action ‖ nonce ‖ pubkey)`, action `backup-read` or `backup-forget`;
   - to store: `sha256("lij-backup-v2" ‖ "backup-push" ‖ nonce ‖ pubkey ‖ fingerprint (32 bytes) ‖ version (8 bytes,
     big-endian))` — the proof binds this exact copy and its number, so a captured proof cannot store anything else.
     (`nonce` and `pubkey` enter as bytes, not as hex text.)
3. `POST /backup` `{ pubkey_hex, nonce, signature, auth_v: 2, blob: <the envelope> }`:
   - `blob.pubkey_hex` must equal the signer's key;
   - the same `version` with the same fingerprint as the stored copy → `{ ok: true, repeat: true }` (a retry after a
     lost answer is not a conflict);
   - a `version` not above the stored one → **409**, "Stale backup rejected" — an older copy can never replace a newer
     one;
   - otherwise stored; the answer carries the version and the fingerprint. Body cap 8 MB.
4. `POST /backup/fetch` `{ pubkey_hex, nonce, signature }` (action `backup-read`) → `{ found: true, blob }`, or
   `{ found: false }`.
5. `POST /backup/meta` (action `backup-read`) → the stored copy's `version`, `saved_at_ms` and fingerprint only — a
   wallet compares before it loads anything.
6. `POST /backup/forget` (action `backup-forget`) → the copy is deleted; only the key that wrote it can do this.

**One wallet, one open copy.** A channel backup restored on a second device must not run beside the first: two copies
signing the same channels is how a channel is lost. The provider's part is in `docs/lijox-copy-guard-standard.md`
(`POST /lsps/registry/my-channels` and the 60-second open-copy window); a wallet MUST follow it before it reconnects
restored channels.

## 5. Next — what the backup must say about itself (not built)

1. **A payload label in the envelope**: `"payload": "ldk-0.2"` (or the next engine's label). A copy without one is read
   as `"ldk-0.2"`. A wallet that cannot read a label says so and offers the exit (item 2) instead of failing.
2. **An exit section inside the seal, readable by any engine**: the same per-channel data as the Black start kit — the
   fully signed latest close and the signed sweep of the user's share to a 12-word address — refreshed with every copy.
   Any LIJOX wallet, on any engine, can then at least close every channel cleanly from the channel backup alone.
3. **The engine-neutral channel state** (§8) beside the engine's own records, once it is defined.

## 6. Next — where copies live (not built)

- A wallet MAY keep its channel backup at more than one backup server; it writes the same envelope to each and, on
  restore, takes the highest `version` whose seal opens and whose fingerprint matches what the server reported.
- **Who may run a backup server**: the user, a LIJOX provider, or anyone. A provider that offers one names it in its
  registry record (`backup_endpoints`: a list of URLs — the Session 35 proposal, `backup_endpoint`, made a list). The
  user may add their own. Changing provider never moves or deletes a backup (Session 22: the backup is the user's, not
  the provider's).
- **A VSS server underneath** (LDK's Versioned Storage Service): allowed as a backup server once mapped — one VSS key
  per backup identity, the envelope as the value, VSS's own version as a check beside ours, and its signature login on
  the `m/525h` key. DP 2026-10-29: VSS gets "a full vetting before we convert or add"; this paragraph is the place it
  lands if the vetting passes.

## 7. What the standard promises a user (today and next)

- Today: lose the phone, keep the 12 words → any LiJ wallet, on any device, brings the channels back open, with the
  same provider (§1–§4).
- Next (§5): any LIJOX wallet, on any engine, can at least close the channels from the channel backup; a wallet on the
  same engine continues them.
- The objective (§8): any LIJOX wallet, on any engine, continues them.

## 8. The objective — an engine-neutral channel state, and engines that import it

Every Lightning engine (LDK, LND, Core Lightning, Eclair) keeps a channel's live state in its own private format, and
none of them today can take in a channel another engine was running. That is why a user's channels are tied to the
software that opened them, even when the user's keys are not. LIJOX's objective is to end that tie: a user can leave
one wallet for another wallet that follows this standard — from another company, or one they build themselves — keep
the same provider, and keep the same channels open.

That takes two things, and this standard commits to both:

1. **A channel record any engine can read** — one per channel, holding what the Lightning specifications (BOLT 2 and
   3) need to carry a channel on: the funding outpoint and channel id; the channel type and its features; both sides'
   parameters (dust limits, reserves, delays, HTLC limits); both sides' public base points and the derivation index of
   the user's own channel keys (so the private keys come again from the 12 words, never stored); the latest commitment
   numbers; the user's latest commitment transaction with the provider's signatures; the provider's latest per-commitment
   point; every revocation secret the provider has given (so an old state can always be punished); every payment in
   flight, with any preimages known; the current fee rate; and any close in progress with its scripts.
2. **Engines that import it** — starting with LDK (LiJ's own engine), by proposing the import to its maintainers with
   the record and a working converter; then LND and Core Lightning.

Until both exist, the standard says what it says today (§7) and no user-facing copy claims more.
