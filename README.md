# LIJOX

An open, permissionless registry protocol for Lightning service providers (LSPs), and the registry worker that implements it. Wallets built on it — [Lightning in a Jar](https://github.com/dav1dpgit/lightninginajar) is the first — discover LSPs from one or more registries, connect to the one they choose, and switch. Operators run the LSP side with the [LIJOX adapter](https://github.com/dav1dpgit/lijox-lnd-adapter) on their existing LND node.

LIJOX is not a federation. Anyone can publish a registry; wallets aggregate across registries on their own; the only discipline is the market — fees and behaviour, not membership. An LSP that participates serves any wallet that speaks the standard.

**Status: pre-release, one live registry (`lij-worker.dp-a95.workers.dev`), two registered LSPs, both run by the standard's author.** That concentration is stated in the wallet's README as well; it changes when other operators register.

## What is in this repository

```
lij-worker/          the registry worker (Cloudflare Workers + KV), src/index.js
                     test-register-sig.mjs — the sign↔verify gate CI runs before deploy
docs/                the protocol and design records (informal, written as they were decided)
.github/workflows/   lij-worker-deploy.yml — CI deploy of the worker
```

## The registry worker — routes

| route | who calls it | what it does |
|---|---|---|
| `GET /lsps` | wallets | the registry: name, endpoint, WSS URL, fees, channel limits, capabilities per LSP, plus `last_seen_ms`, `first_registered_at` and `stale` (no registration for 24 h — adapters ≥0.71 re-register every 6 h). Signatures and timestamps are checked on the way in and stripped on the way out. |
| `POST /lsps/register` | LSPs | `lijox-register:v1` — the LSP signs its full advertised field set plus a timestamp with its node key (LND `signmessage`); the worker verifies by public-key recovery, ±600 s. |
| `POST /lsps/unregister` | LSPs | `lijox-unregister:v1` (0.6.0) — a signed departure (pubkey + ts); the ts must be newer than the current registration's, so a captured request cannot be replayed against a later re-registration. The record is deleted. |
| `PUT` / `GET /lsp-backup` | LSPs | `lijox-scb:v1` — an LSP's own `channel.backup` (LND's seed-encrypted SCB), keyed and signed by its node key; latest + one previous generation, 5 MB cap. |
| `GET /backup/challenge`, `POST /backup`, `POST /backup/fetch` | wallets | the wallet's sealed state blob: a single-use nonce is signed with the wallet's seed-derived portable key (compact ECDSA over a domain-separated sha256); versioned, latest wins. Contents are AES-GCM under a key only the seed produces; the worker sees a pubkey, a size and timing. |
| `POST /names/claim`, `POST /names/release` | LSPs | `lijox-name:v1` — a Lightning address name at the neutral host, one LSP per name, signed with the LSP's node key. |
| `GET /.well-known/lnurlp/<name>` | payers | the neutral-host LNURL-pay lookup: returns the owning LSP's own answer unchanged (edge-cached 60 s); the payment callback goes straight to that LSP. |
| `POST /lsps1/channel` | wallets | LSPS1 channel request relay (currently disabled server-side). |
| `GET /health` | anyone | liveness. |

Canonical message formats are in `lij-worker/src/index.js` beside their verifiers (`canonicalRegisterMsg`, `canonicalScbPush`/`canonicalScbGet`, the name and backup digests). The adapter carries verbatim twins of the ones it signs; a change ships in both repositories in the same release.

Two LSP-side routes the standard also names live in the adapter, not the worker: `POST /lsps/registry/recover-close` (a wallet back with only its 12 words asks its LSP to force-close every channel held under its node key; all-or-nothing while any HTLC is in flight) and the LNURL-pay rail (`/.well-known/lnurlp/<name>` at the LSP's own host, hold invoices minted on wallet-registered hashes; preimages never leave the wallet).

## Documents

- `docs/lijox-provider-definition.md` — what a LIJOX provider is and is not
- `docs/lijox-interface-v0.md` — the wallet-side interface, postures, build order
- `docs/openintent-v1.md` — Open-Intent v1 (channel-open intents)
- `docs/static-address-model.md` — the LNURL-pay rail contract: seed-derived preimages, hash expiry, a pay code belongs to the wallet's current LSP, a definitive refusal ends the payment
- `docs/lijox-watchtower-note.md` — the reciprocal-watchtower obligation (ruled, not yet built)
- `docs/design-22-lijox-sybil-ddos.md`, `docs/adapter-plain-terms.md`, `docs/lijox-manifest-arc-plan.md`

## Running your own registry

`lij-worker/` deploys with Wrangler to any Cloudflare account: create a KV namespace, put its id in `wrangler.toml`, `wrangler deploy`. The CI workflow does the same from a `CLOUDFLARE_API_TOKEN` secret and refuses to deploy if the local sign↔verify gate fails. A registry is a list; nothing in the protocol makes one registry more official than another.

## License

MIT — see [LICENSE](LICENSE). The names, logo and site are not licensed — see [TRADEMARKS.md](TRADEMARKS.md).
