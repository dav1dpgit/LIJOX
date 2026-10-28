// Lightning-in-a-Jar Worker
// Deployed at: lij-worker.dp-a95.workers.dev
// Future: api.lightninginajar.xyz
//
// Routes:
//   GET  /health              — health check
//   GET  /lsps                — list registered LSPs ranked by score
//   POST /lsps/register       — register an LSP node (lijox-register:v1 —
//                               LND-signed over the full field set, ±600s ts;
//                               v2 when the record offers a block-filter server;
//                               v3 with a tatara block; v4 with a routes list)
//   PUT  /lsp-backup          — LSP pushes its own channel.backup (SCB),
//                               node-key signed (lijox-scb:v1); GET restores
//   POST /backup              — push encrypted wallet state (auth required)
//   GET  /backup/:pubkey      — pull encrypted wallet state (auth required)

import * as secp from '@noble/secp256k1';
// 0.17.0 (S63, Phase C): the rules the two doors of the registry share — the clock on every write, the tombstone on
// every delete, the record guards, the mirror's signed message (src/mirror.js; the box imports the same file)
import { clockedStore, mirrorable, clockOf, recordAllows, mirrorMsg, sha256Hex, MIRROR_TS_WINDOW_S, TOMB_PREFIX, TOMB_TTL_S } from './mirror.js';

const CORS = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
  'Access-Control-Allow-Headers': 'Content-Type, Authorization',
  // v0.4.1 (S41, DP freshness order): every answer here is dynamic state —
  // no cache anywhere gets discretion over it. KV's own <=60s propagation
  // is the only staleness that remains, and that one is physics.
  'Cache-Control': 'no-store',
};

function json(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { 'Content-Type': 'application/json', ...CORS },
  });
}

function err(msg, status = 400) {
  return json({ error: msg }, status);
}

// 0.16.0 (S63, Kimi round 2 K3/K8 — DP's numbers): THE RATE LIMIT, per client address, through a Workers rate-limit
// binding (approximate, per Cloudflare location). RL_REGISTER 60/min on the registry writes; RL_WRITE 300/min on the
// other write routes. No binding (the tests' env) → nothing is limited.
async function rateLimited(env, bindingName, request) {
  const rl = env && env[bindingName];
  if (!rl || typeof rl.limit !== 'function') return null;
  const ip = String(request.headers.get('cf-connecting-ip') || request.headers.get('x-real-ip') || 'unknown');
  let ok = true;
  try { const r = await rl.limit({ key: bindingName + ':' + ip }); ok = !r || r.success !== false; } catch (_) { ok = true; }   // a binding error never refuses a wallet
  return ok ? null : err('too many requests from this address — try again in a minute', 429);
}
// 0.14.0 (K8): the body's declared size, checked BEFORE it is read (a missing header passes — the post-read checks stay)
function tooLarge(request, cap) {
  const len = Number(request.headers.get('content-length'));
  return Number.isFinite(len) && len > cap;
}
// 0.14.0 (K3): a KV listing that follows its cursor and reads in bulk (100 keys an operation) — the old loop stopped at
// KV's first page and spent one operation per record
async function kvGetMany(env, names) {
  const out = new Map();
  for (let i = 0; i < names.length; i += 100) {
    const chunk = names.slice(i, i + 100);
    let got = null;
    try { got = await env.LIJ_KV.get(chunk); } catch (_) { got = null; }
    if (got && typeof got.get === 'function') { for (const n of chunk) out.set(n, got.get(n) ?? null); }
    else { for (const n of chunk) out.set(n, await env.LIJ_KV.get(n)); }
  }
  return out;
}
async function kvListAll(env, prefix, cap = 5000) {
  const names = []; let cursor = undefined;
  for (let page = 0; page < 50; page++) {
    const r = await env.LIJ_KV.list(cursor ? { prefix, cursor } : { prefix });
    for (const k of (r.keys || [])) { names.push(k.name); if (names.length >= cap) return names; }
    if (r.list_complete !== false || !r.cursor) break;
    cursor = r.cursor;
  }
  return names;
}

// ── Signed-challenge auth for /backup ───────────────────────────────────────
// No shared secret. The client proves control of the portable key that indexes
// its backup by signing a server-issued nonce. Digest must match the client's
// build exactly: sha256("lij-backup-v1" || action || nonce || pubkey).

const BACKUP_DOMAIN = new TextEncoder().encode('lij-backup-v1');

function hexToBytes(hex) {
  if (typeof hex !== 'string' || hex.length % 2 !== 0) return null;
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) {
    const b = parseInt(hex.substr(i * 2, 2), 16);
    if (Number.isNaN(b)) return null;
    out[i] = b;
  }
  return out;
}

// 0.10.0: a copy's fingerprint — sha256 over its sealed bytes (`encrypted_data`, the engine's byte array), hex. The
// engine takes the same hash of the same bytes before it uploads (lij-core storage::backup_fingerprint). null when the
// copy carries no byte array (nothing to fingerprint — the copy is stored as before).
async function blobFingerprint(blob) {
  const d = blob && blob.encrypted_data;
  if (!Array.isArray(d) || d.length === 0) return null;
  const bytes = new Uint8Array(d.length);
  for (let i = 0; i < d.length; i++) {
    const v = d[i];
    if (typeof v !== 'number' || !Number.isInteger(v) || v < 0 || v > 255) return null;
    bytes[i] = v;
  }
  const h = new Uint8Array(await crypto.subtle.digest('SHA-256', bytes));
  let out = '';
  for (let i = 0; i < h.length; i++) out += h[i].toString(16).padStart(2, '0');
  return out;
}

async function backupDigest(action, nonceHex, pubkeyHex) {
  const actionB = new TextEncoder().encode(action);
  const nonceB = hexToBytes(nonceHex);
  const pubkeyB = hexToBytes(pubkeyHex);
  if (!nonceB || !pubkeyB) return null;
  const pre = new Uint8Array(
    BACKUP_DOMAIN.length + actionB.length + nonceB.length + pubkeyB.length
  );
  let o = 0;
  pre.set(BACKUP_DOMAIN, o); o += BACKUP_DOMAIN.length;
  pre.set(actionB, o); o += actionB.length;
  pre.set(nonceB, o); o += nonceB.length;
  pre.set(pubkeyB, o);
  return new Uint8Array(await crypto.subtle.digest('SHA-256', pre));
}

// 0.18.0 (S64, Kimi K3.1 Pro round 2, K6a — engine v358): THE PUSH'S PROOF BINDS THE COPY. The v1 digest was
// action‖nonce‖pubkey alone, so an authorisation captured on the path could push ANY copy at ANY number under it. The
// v2 digest adds the copy's fingerprint (sha256 of its sealed bytes, the same the engine takes — blobFingerprint) and
// its number (8 bytes big-endian): sha256("lij-backup-v2" || action || nonce || pubkey || fingerprint || version).
// A push whose body says `auth_v: 2` is verified this way; a v1 push (an engine before v358) is still taken for ONE
// release; the next retires v1 for the push. The reads and the forget carry no copy and keep v1.
const BACKUP_DOMAIN_V2 = new TextEncoder().encode('lij-backup-v2');
async function backupDigestV2(action, nonceHex, pubkeyHex, fingerprintHex, version) {
  const actionB = new TextEncoder().encode(action);
  const nonceB = hexToBytes(nonceHex);
  const pubkeyB = hexToBytes(pubkeyHex);
  const fpB = hexToBytes(fingerprintHex || '');
  if (!nonceB || !pubkeyB || !fpB || fpB.length !== 32 || !Number.isSafeInteger(version) || version < 0) return null;
  const verB = new Uint8Array(8); new DataView(verB.buffer).setBigUint64(0, BigInt(version));
  const pre = new Uint8Array(BACKUP_DOMAIN_V2.length + actionB.length + nonceB.length + pubkeyB.length + 32 + 8);
  let o = 0;
  pre.set(BACKUP_DOMAIN_V2, o); o += BACKUP_DOMAIN_V2.length;
  pre.set(actionB, o); o += actionB.length;
  pre.set(nonceB, o); o += nonceB.length;
  pre.set(pubkeyB, o); o += pubkeyB.length;
  pre.set(fpB, o); o += 32;
  pre.set(verB, o);
  return new Uint8Array(await crypto.subtle.digest('SHA-256', pre));
}

// Verify a server-issued nonce + secp256k1 signature for `action` over the
// digest. Single-use: the challenge is deleted on success by the caller.
// 0.18.0: `bind` = { fingerprint, version } verifies the v2 digest over the copy instead of the v1 one.
async function verifyBackupAuth(env, action, pubkeyHex, nonce, sigHex, bind) {
  if (!pubkeyHex || !nonce || !sigHex) return false;
  if (typeof nonce !== 'string' || !/^[0-9a-f]{64}$/.test(nonce)) return false;
  const stored = await env.LIJ_KV.get(`bkpchal:${pubkeyHex}:${nonce}`);   // 0.14.0 (K4): keyed by nonce — nobody overwrites another wallet's open challenge
  if (!stored || stored !== nonce) return false;
  const digest = bind ? await backupDigestV2(action, nonce, pubkeyHex, bind.fingerprint, bind.version) : await backupDigest(action, nonce, pubkeyHex);
  const sig = hexToBytes(sigHex);
  const pub = hexToBytes(pubkeyHex);
  if (!digest || !sig || !pub) return false;
  try {
    return secp.verify(sig, digest, pub);
  } catch (_) {
    return false;
  }
}

// ── lijox-register:v1 — signed registration (S41, review #2 fix) ────────────
// Registration must PROVE control of the claimed node key. The LSP signs with
// its node identity key via LND signmessage; the worker verifies by public-key
// recovery. The signature binds EVERY advertised field, so no part of a
// registry record can be altered after signing — not by a replayer inside the
// freshness window, not by the registry itself.
//
// Canonical message: 'lijox-register:v1:' + fields below, each percent-encoded
// (JS encodeURIComponent — RFC 3986 unreserved set, so the ':' joiner can
// never appear inside a field), joined with ':'.
// Field order:  pubkey, ts, name, endpoint, wss_url, route_endpoint,
//               route_macaroon, fee_ppm, fee_base_sats, channel_open_fee_sats,
//               max_channel_size_sats, supports_jit
// Encodings:    strings as-is (null/undefined → ''), numbers as decimal
//               strings (absent/NaN → '0'), booleans '1'/'0'. ts = unix secs.
// 0.8.0 (S52, DP 2026-09-30 23:09 — each LIJOX provider may offer its own
// block-filter server): a record that offers one is signed as
// 'lijox-register:v2:' + the v1 fields + filter_url + filter_sp ('1'/'0'). A
// record without one is signed as v1, byte for byte as before — adapters older
// than 0.87.0 register unchanged. Stripping or adding filter_url changes the
// prefix and the field list, so neither verifies against the other's signature.
// 0.11.0 (S58, LIJOX's Tatara step 4 — spec v0.10 §11.2): a record that offers Tatara pools is signed as
// 'lijox-register:v3:' + the v1 fields + filter_url ('' when none) + filter_sp + the `tatara` block's fields in
// TATARA_FIELDS order (lists comma-joined, booleans '1'/'0', absent strings ''). Records without the block sign as v1
// or v2, byte for byte as before. Stripping, adding or changing the block changes the message, so none verifies
// against another's signature.
// 0.12.0 (S59, DP 2026-10-14 — pools per route differently sized): the v3 rule "every channel size among the sizes" is
// gone — the channel list is the provider's own. (0.12.0 also took a `close_sizes` list signed as v4; DP ruled the same
// day that a channel's coin after its close sits in the on-chain pools, so 0.12.1 removed it — the message is v3 again,
// byte for byte as 0.11.0 signed it; no record ever carried the key.)
// 0.13.0 (S61, DP 2026-10-19 14:54 — Step A, "both routes"; docs/design/routes/routes-r1.md §2): a record that carries
// a `routes` list is signed as 'lijox-register:v4:' + the v1 fields + filter_url ('' when none) + filter_sp + the
// tatara block's fields in TATARA_FIELDS order ('' / '0' for every field when no block is offered) + ONE field holding
// every route as reach|endpoint|wss_url|filter_url, routes joined by ';' (the '|' and ';' are inside the field and
// percent-encoded with it). A route's `reach` is the operator's signed word for what sits between the wallet and the
// box: direct (TLS ends on the operator's own machine), cloudflare (Cloudflare's edge ends TLS), tor (a slot). The
// first route repeats the top-level endpoint / wss_url / filter_url, so a v3 reader sees the operator's first choice.
// Records without routes sign as v1/v2/v3, byte for byte as before. (0.12.0's one-day 'v4' carried close_sizes and
// was retired by 0.12.1 the same day; no record ever carried it, so the prefix is free.)
// This function is duplicated VERBATIM in lij-adapter.js (the signer). Any
// change here changes there in the same release, or registration 403s.
function canonicalRegisterMsg(f) {
  const s = (v) => (v === null || v === undefined) ? '' : String(v);
  const n = (v) => String(Number(v) || 0);
  const fields = [
    s(f.pubkey), n(f.ts), s(f.name), s(f.endpoint), s(f.wss_url),
    s(f.route_endpoint), s(f.route_macaroon),
    n(f.fee_ppm), n(f.fee_base_sats), n(f.channel_open_fee_sats),
    n(f.max_channel_size_sats), (f.supports_jit ? '1' : '0'),
  ];
  if (f.routes && f.routes.length) {
    const t = f.tatara || {};
    const tf = TATARA_FIELDS.map(([k, kind]) => kind === 'list' ? (t[k] || []).map((x) => n(x)).join(',')
      : kind === 'bool' ? (t[k] ? '1' : '0') : kind === 'int' ? n(t[k]) : s(t[k]));
    const rf = f.routes.map((r) => [s(r.reach), s(r.endpoint), s(r.wss_url), s(r.filter_url)].join('|')).join(';');
    return 'lijox-register:v4:' + fields.concat([s(f.filter_url), (f.filter_sp ? '1' : '0')], tf, [rf]).map(encodeURIComponent).join(':');
  }
  if (f.tatara) {
    const t = f.tatara;
    const tf = TATARA_FIELDS.map(([k, kind]) => kind === 'list' ? (t[k] || []).map((x) => n(x)).join(',')
      : kind === 'bool' ? (t[k] ? '1' : '0') : kind === 'int' ? n(t[k]) : s(t[k]));
    return 'lijox-register:v3:' + fields.concat([s(f.filter_url), (f.filter_sp ? '1' : '0')], tf).map(encodeURIComponent).join(':');
  }
  if (f.filter_url) {
    return 'lijox-register:v2:' + fields.concat([s(f.filter_url), (f.filter_sp ? '1' : '0')]).map(encodeURIComponent).join(':');
  }
  return 'lijox-register:v1:' + fields.map(encodeURIComponent).join(':');
}

// 0.8.0: a provider's block-filter server address — https only, a host, an
// optional :port and path of URL-safe characters, no trailing '/', 200
// characters at most (the wallet engine's clean_filter_base, v296, is the same
// rule). Absent/empty → null; anything else that fails → undefined (refused).
const FILTER_URL_RE = /^https:\/\/[A-Za-z0-9][A-Za-z0-9.-]*(:[0-9]{1,5})?(\/[A-Za-z0-9._~\/-]*)?$/;
function cleanFilterUrl(v) {
  if (v === undefined || v === null || v === '') return null;
  const t = String(v);
  if (t.length > 200 || t.endsWith('/') || !FILTER_URL_RE.test(t)) return undefined;
  return t;
}

// 0.11.0 (S58, Tatara step 4): the `tatara` block — the provider's pool settings, declared upfront and signed (spec
// v0.10 §11). Field order is the canonical order. The registry refuses no provider for its policy (the LIJOX baseline;
// the wallets decide): the checks here are of shape only, and every key must be one of these — nothing unsigned is
// stored. Absent/null → null (no Tatara offered); a malformed block → undefined (refused).
const TATARA_FIELDS = [
  ['v', 'int'], ['sizes', 'list'], ['min_people', 'int'], ['max_people', 'int'], ['countdown_s', 'int'],
  ['wake_window_s', 'int'], ['max_retries', 'int'], ['strikes', 'int'], ['max_pools_per_size', 'int'],
  ['max_pools_total', 'int'], ['max_list_per_size', 'int'], ['max_fee_rate', 'int'], ['channel_pools', 'bool'],
  ['channel_sizes', 'list'], ['relay_url', 'str'], ['relay_for_others', 'bool'], ['forward_payouts', 'bool'],
  ['forward_coin_checks', 'bool'], ['coin_check_url', 'str'], ['ring_hash', 'str'],
];
const TATARA_LIMITS = {
  v: [1, 1], min_people: [2, 100], max_people: [2, 100], countdown_s: [0, 86400], wake_window_s: [0, 86400],
  max_retries: [0, 100], strikes: [1, 100], max_pools_per_size: [1, 1000], max_pools_total: [1, 10000],
  max_list_per_size: [1, 100000], max_fee_rate: [1, 10000],
};
const RELAY_URL_RE = /^wss:\/\/[A-Za-z0-9][A-Za-z0-9.-]*(:[0-9]{1,5})?(\/[A-Za-z0-9._~\/-]*)?$/;
function cleanTatara(v) {
  if (v === undefined || v === null) return null;
  if (typeof v !== 'object' || Array.isArray(v)) return undefined;
  const known = new Set(TATARA_FIELDS.map(([k]) => k));
  if (Object.keys(v).some((k) => !known.has(k))) return undefined;
  const int = (x, lo, hi) => Number.isSafeInteger(x) && x >= lo && x <= hi;
  const list = (a) => Array.isArray(a) && a.length <= 12 && a.every((x) => int(x, 1, 2100000000000000)) && a.every((x, i) => i === 0 || x > a[i - 1]);
  const bool = (x) => x === true || x === false;
  for (const [k, [lo, hi]] of Object.entries(TATARA_LIMITS)) if (!int(v[k], lo, hi)) return undefined;
  if (v.min_people > v.max_people) return undefined;
  if (!list(v.sizes) || v.sizes.length < 1) return undefined;
  for (const k of ['channel_pools', 'relay_for_others', 'forward_payouts', 'forward_coin_checks']) if (!bool(v[k])) return undefined;
  const ch = v.channel_sizes === undefined || v.channel_sizes === null ? [] : v.channel_sizes;
  if (!list(ch) || (!v.channel_pools && ch.length) || (v.channel_pools && !ch.length)) return undefined;   // 0.12.0: a channel size need not be an on-chain size
  const relay = String(v.relay_url || '');
  if (relay.length > 200 || relay.endsWith('/') || !RELAY_URL_RE.test(relay)) return undefined;
  const coin = (v.coin_check_url === undefined || v.coin_check_url === null || v.coin_check_url === '') ? null : cleanFilterUrl(v.coin_check_url);
  if (coin === undefined) return undefined;
  const ring = (v.ring_hash === undefined || v.ring_hash === null || v.ring_hash === '') ? null : String(v.ring_hash);
  if (ring !== null && !/^[0-9a-f]{64}$/.test(ring)) return undefined;
  const out = {};
  for (const [k] of TATARA_FIELDS) out[k] = v[k];
  out.channel_sizes = ch; out.relay_url = relay; out.coin_check_url = coin; out.ring_hash = ring;
  return out;
}

// 0.13.0 (S61, Step A): the `routes` list — every door into the same provider, in the operator's order of preference.
// Shape only (the registry refuses no provider for its policy): 1–3 routes; each exactly {reach, endpoint, wss_url,
// filter_url}; reach one of the three words; endpoint a plain https:// address and wss_url a plain wss:// address (the
// filter_url rule: a host, an optional :port and path, no trailing '/', 200 characters at most); filter_url by
// cleanFilterUrl (absent/'' → null: that route reads the default filter server); no two routes with the same endpoint.
// Absent/null → null (a one-door record, v1/v2/v3); malformed → undefined (refused). The first route must repeat the
// record's own endpoint / wss_url / filter_url — the handler checks that, not this function.
const ROUTE_REACH = ['direct', 'cloudflare', 'tor'];
const ROUTE_KEYS = ['reach', 'endpoint', 'wss_url', 'filter_url'];
function cleanRoutes(v) {
  if (v === undefined || v === null) return null;
  if (!Array.isArray(v) || v.length < 1 || v.length > 3) return undefined;
  const out = [];
  for (const r of v) {
    if (!r || typeof r !== 'object' || Array.isArray(r)) return undefined;
    if (Object.keys(r).some((k) => !ROUTE_KEYS.includes(k))) return undefined;
    if (!ROUTE_REACH.includes(r.reach)) return undefined;
    const ep = cleanFilterUrl(r.endpoint);                       // the same https address rule
    if (!ep) return undefined;                                    // null (absent) or undefined (bad) — both refused
    const ws = String(r.wss_url || '');
    if (ws.length > 200 || ws.endsWith('/') || !RELAY_URL_RE.test(ws)) return undefined;
    const fu = cleanFilterUrl(r.filter_url);
    if (fu === undefined) return undefined;
    if (out.some((o) => o.endpoint === ep)) return undefined;
    out.push({ reach: r.reach, endpoint: ep, wss_url: ws, filter_url: fu });
  }
  return out;
}

// 0.6.0 (S45, #6 registry hygiene): an LSP leaves the list with a signed
// request. Canonical: pubkey + ts only; ts must be NEWER than the current
// registration's ts, so a captured unregister cannot be replayed against a
// later re-registration. Duplicated VERBATIM in lij-adapter.js.
function canonicalUnregisterMsg(pubkey, ts) {
  return 'lijox-unregister:v1:' + [String(pubkey), String(Number(ts) || 0)].map(encodeURIComponent).join(':');
}

// zbase32 (Tor/LND alphabet) — LND signmessage output encoding.
const ZB32 = 'ybndrfg8ejkmcpqxot1uwisza345h769';
function zbase32Decode(str) {
  let bits = 0, acc = 0;
  const out = [];
  for (const ch of String(str).toLowerCase()) {
    const v = ZB32.indexOf(ch);
    if (v < 0) return null;
    acc = (acc << 5) | v; bits += 5;
    if (bits >= 8) { bits -= 8; out.push((acc >>> bits) & 0xff); }
  }
  return new Uint8Array(out);
}

// Verify an LND signmessage signature: zbase32(65-byte compact-recoverable
// ECDSA) over dsha256('Lightning Signed Message:' + msg), header byte
// 27 + 4 + recId (btcec SignCompact, compressed). True iff the recovered key
// IS the claimed pubkey. Returns boolean, never throws.
async function verifyLndSignedRegistration(pubkeyHex, msg, sigZbase32) {
  try {
    const sig = zbase32Decode(sigZbase32);
    if (!sig || sig.length !== 65) return false;
    const header = sig[0];
    if (header < 27 || header > 34) return false;
    const recId = (header - 27) & 3;
    const pre = new TextEncoder().encode('Lightning Signed Message:' + msg);
    const h1 = new Uint8Array(await crypto.subtle.digest('SHA-256', pre));
    const digest = new Uint8Array(await crypto.subtle.digest('SHA-256', h1));
    const recovered = secp.Signature.fromCompact(sig.slice(1))
      .addRecoveryBit(recId)
      .recoverPublicKey(digest);
    return recovered.toHex(true) === String(pubkeyHex).toLowerCase();
  } catch (_) {
    return false;
  }
}

// ── lijox-scb:v1 — the LSP's own channel.backup, two-location cloud leg ─────
// S41 channel-backup arc (DP design: every-change → LAN Umbrel, daily → here).
// The SCB is encrypted by LND under the node seed, so this is untrusted
// storage by construction. Auth = the node key itself via LND signmessage —
// no bearer secrets to mint or leak; the blob hash rides inside the signed
// push message so identity and integrity are one check. Retention: latest +
// one previous generation (the week of history lives on the operator's LAN).
function canonicalScbPush(pubkey, ts, sha256hex) {
  return `lijox-scbpush:v1:${pubkey}:${ts}:${sha256hex}`;
}
function canonicalScbGet(pubkey, ts) {
  return `lijox-scbget:v1:${pubkey}:${ts}`;
}
async function sha256HexOf(bytes) {
  const d = new Uint8Array(await crypto.subtle.digest('SHA-256', bytes));
  return Array.from(d).map(b => b.toString(16).padStart(2, '0')).join('');
}

export default {
  async fetch(request, env0) {
    // 0.17.0 (Phase C): every write this request makes carries the request's clock, and a delete leaves a tombstone —
    // the other door of the registry (the box) reads both to keep the two stores level. The routes below see the
    // wrapped store; the mirror routes alone read and write the raw one with the clocks they are handed.
    const rawKv = env0 && env0.LIJ_KV;
    const env = rawKv ? Object.assign({}, env0, { LIJ_KV: clockedStore(rawKv, Date.now()) }) : env0;
    const url = new URL(request.url);
    const path = url.pathname;
    const method = request.method;

    // CORS preflight
    if (method === 'OPTIONS') {
      return new Response(null, { headers: CORS });
    }

    // ── Names (0.5.0, S43 — DP: @lightninginajar.xyz, non-portable) ─────────
    // A name is claimed by the LSP that holds the wallet's channel, signed
    // with that LSP's node key (LND signmessage, same scheme as /lsps/register).
    // The record is name -> lsp pubkey; it never moves — a switch releases at
    // the old LSP and re-claims at the new one. The worker is neutral: any LSP
    // registered here may claim. Lookups at lightninginajar.xyz/.well-known/
    // lnurlp/<name> return the LSP's own answer unchanged, cached 60 s at the
    // edge, so this worker sees cache misses, not payers; the callback inside
    // that answer points at the LSP, never here.
    const NAME_RE = /^[a-z0-9_-]{2,32}$/;
    // 0.15.0 (K1): the transfer op's message carries the NEW LSP's pubkey as a fifth part — `transfer:<name>:<oldpk>:<ts>:<newpk>`
    const nameMsg = (kind, name, pk, ts, extra) => 'lijox-name:v1:' + [kind, name, pk, String(Number(ts) || 0)].concat(extra !== undefined ? [extra] : []).map(encodeURIComponent).join(':');
    const nameAuth = async (body, kind, extra) => {
      const name = String(body && body.name || '').toLowerCase();
      const pk = String(body && body.lsp_pubkey || '').toLowerCase();
      const ts = Number(body && body.ts);
      if (!NAME_RE.test(name)) return { e: err('bad name') };
      const pkb = hexToBytes(pk); if (!pkb || pkb.length !== 33) return { e: err('bad lsp_pubkey') };
      if (!Number.isFinite(ts) || Math.abs(Date.now() / 1000 - ts) > 600) return { e: err('ts outside window', 403) };
      if (!(await env.LIJ_KV.get(`lsp:${pk}`))) return { e: err('unknown LSP', 403) };
      const ok = await verifyLndSignedRegistration(pk, nameMsg(kind, name, pk, ts, extra), String(body.signature || ''));
      if (!ok) return { e: err('signature does not verify', 403) };
      return { name, pk };
    };
    if (path === '/names/claim' && method === 'POST') {
      { const lim = await rateLimited(env, 'RL_WRITE', request); if (lim) return lim; }   // 0.16.0: 300/min per address
      if (tooLarge(request, 64 * 1024)) return err('body exceeds the 64 KB cap', 413);   // 0.14.0 (K8)
      let body; try { body = await request.json(); } catch (_) { return err('Invalid JSON'); }
      const a = await nameAuth(body, 'claim'); if (a.e) return a.e;
      const cur = await env.LIJ_KV.get(`name:${a.name}`, 'json');
      if (cur && cur.lsp_pubkey !== a.pk) return err('name taken', 409);
      if (!cur) await env.LIJ_KV.put(`name:${a.name}`, JSON.stringify({ lsp_pubkey: a.pk, claimed_at: Date.now() }));
      return json({ ok: true, name: a.name, lsp_pubkey: a.pk, existed: !!cur });
    }
    // 0.15.0 (S63, Kimi round 2 K1 — DP "Agreed"): the signed TRANSFER. The old LSP hands the name to the new one in
    // one put — no free interval in which any registered LSP could take it. The old LSP signs the new LSP's pubkey;
    // the new LSP must be registered here; the name must be the old LSP's (an unheld name is simply claimed for the
    // new one). A later /names/claim by the new LSP answers existed:true.
    if (path === '/names/transfer' && method === 'POST') {
      { const lim = await rateLimited(env, 'RL_WRITE', request); if (lim) return lim; }   // 0.16.0: 300/min per address
      if (tooLarge(request, 64 * 1024)) return err('body exceeds the 64 KB cap', 413);
      let body; try { body = await request.json(); } catch (_) { return err('Invalid JSON'); }
      const to = String(body && body.to_lsp_pubkey || '').toLowerCase();
      const tob = hexToBytes(to); if (!tob || tob.length !== 33 || !/^[0-9a-f]{66}$/.test(to)) return err('bad to_lsp_pubkey');
      const a = await nameAuth(body, 'transfer', to); if (a.e) return a.e;
      if (to === a.pk) return err('to_lsp_pubkey is the signer', 400);
      if (!(await env.LIJ_KV.get(`lsp:${to}`))) return err('unknown LSP (to)', 403);
      const cur = await env.LIJ_KV.get(`name:${a.name}`, 'json');
      if (cur && cur.lsp_pubkey !== a.pk) return err('not yours', 403);
      await env.LIJ_KV.put(`name:${a.name}`, JSON.stringify({ lsp_pubkey: to, claimed_at: Date.now(), transferred_from: a.pk, transferred_at: Date.now() }));
      return json({ ok: true, name: a.name, lsp_pubkey: to, from: a.pk, existed: !!cur });
    }
    if (path === '/names/release' && method === 'POST') {
      { const lim = await rateLimited(env, 'RL_WRITE', request); if (lim) return lim; }   // 0.16.0: 300/min per address
      if (tooLarge(request, 64 * 1024)) return err('body exceeds the 64 KB cap', 413);   // 0.14.0 (K8)
      let body; try { body = await request.json(); } catch (_) { return err('Invalid JSON'); }
      const a = await nameAuth(body, 'release'); if (a.e) return a.e;
      const cur = await env.LIJ_KV.get(`name:${a.name}`, 'json');
      if (cur && cur.lsp_pubkey !== a.pk) return err('not yours', 403);
      if (cur) await env.LIJ_KV.delete(`name:${a.name}`);
      return json({ ok: true, name: a.name, released: !!cur });
    }
    if (path.startsWith('/.well-known/lnurlp/') && method === 'GET') {
      const name = path.slice('/.well-known/lnurlp/'.length).toLowerCase();
      if (!NAME_RE.test(name)) return json({ status: 'ERROR', reason: 'bad name' }, 400);
      const cache = caches.default;
      const cacheKey = new Request(new URL(`/.well-known/lnurlp/${name}`, 'https://lightninginajar.xyz').toString(), { method: 'GET' });
      const hit = await cache.match(cacheKey);
      if (hit) return hit;
      const rec = await env.LIJ_KV.get(`name:${name}`, 'json');
      if (!rec) return json({ status: 'ERROR', reason: 'unknown name' }, 404);
      const lsp = await env.LIJ_KV.get(`lsp:${rec.lsp_pubkey}`, 'json');
      if (!lsp || !lsp.endpoint) return json({ status: 'ERROR', reason: 'LSP unavailable' }, 503);
      let up;
      // 0.14.0 (K7): no redirect followed (the provider's answer comes from the address it registered, nowhere else) and
      // at most 64 KB of it read. 0.17.1: `redirect: 'manual'` — Workers does not implement the Fetch standard's 'error'
      // mode (a TypeError the moment the Request is built, before anything is sent); 0.14.0–0.17.0 answered 502 "LSP
      // unreachable" to EVERY lookup on Cloudflare for it (DP, 23:06). A 3xx answer is refused here instead.
      try { up = await fetch(String(lsp.endpoint).replace(/\/+$/, '') + '/.well-known/lnurlp/' + name, { cf: { cacheTtl: 0 }, redirect: 'manual' }); }
      catch (_) { return json({ status: 'ERROR', reason: 'LSP unreachable' }, 502); }
      if (up.status >= 300 && up.status < 400) return json({ status: 'ERROR', reason: 'LSP unreachable' }, 502);   // a redirect is not an answer
      let text = '';
      try {
        const reader = up.body && up.body.getReader ? up.body.getReader() : null;
        if (!reader) text = await up.text();
        else {
          const parts = []; let total = 0;
          for (;;) { const { done, value } = await reader.read(); if (done) break; total += value.length; if (total > 64 * 1024) { try { await reader.cancel(); } catch (_) {} return json({ status: 'ERROR', reason: 'LSP answer too large' }, 502); } parts.push(value); }
          text = new TextDecoder().decode(parts.length === 1 ? parts[0] : parts.reduce((a, p) => { const o = new Uint8Array(a.length + p.length); o.set(a); o.set(p, a.length); return o; }, new Uint8Array(0)));
        }
      } catch (_) { return json({ status: 'ERROR', reason: 'LSP unreachable' }, 502); }
      const out = new Response(text, { status: up.status, headers: { ...CORS, 'Content-Type': 'application/json', 'Cache-Control': 'public, max-age=60' } });
      if (up.status === 200) { try { await cache.put(cacheKey, out.clone()); } catch (_) {} }
      return out;
    }

    // ── 0.17.0 (S63, Phase C): THE MIRROR — the box's side of the registry drives it (src/mirror.js) ──────────
    // The listing with clocks, one key's bytes, a put and a delete that apply only when newer. Signed by the box's
    // own key (LIJ_MIRROR_PUBKEY, a wrangler var — empty until the box's first boot prints its pubkey → 503). No
    // rate limit: the one key is the admission; an unsigned call is refused before any store access.
    if (path.startsWith('/mirror/')) {
      const pub = String((env0 && env0.LIJ_MIRROR_PUBKEY) || '').toLowerCase();
      if (!/^[0-9a-f]{66}$/.test(pub)) return err('mirror not configured', 503);
      if (!rawKv) return err('no store', 503);
      const ts = Number(request.headers.get('x-lij-mirror-ts'));
      const sigHex = String(request.headers.get('x-lij-mirror-sig') || '');
      if (!Number.isFinite(ts) || Math.abs(Date.now() / 1000 - ts) > MIRROR_TS_WINDOW_S) return err('mirror ts outside window', 403);
      const bodyBytes = method === 'POST' ? new Uint8Array(await request.arrayBuffer()) : new Uint8Array(0);
      const msg = mirrorMsg(method, url.pathname + url.search, ts, await sha256Hex(bodyBytes));
      const msgDigest = new Uint8Array(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(msg)));
      const sig = hexToBytes(sigHex), pk = hexToBytes(pub);
      let okSig = false;
      try { okSig = !!(sig && sig.length === 64 && pk && secp.verify(sig, msgDigest, pk)); } catch (_) { okSig = false; }
      if (!okSig) return err('mirror signature does not verify', 403);
      const getMeta = async (k, type) => (typeof rawKv.getWithMetadata === 'function' ? rawKv.getWithMetadata(k, type) : { value: await rawKv.get(k, type), metadata: null });
      const present = (g) => !!(g && g.value !== null && g.value !== undefined);
      if (path === '/mirror/keys' && method === 'GET') {
        const cursor = url.searchParams.get('cursor') || undefined;
        const r = await rawKv.list(cursor ? { cursor, limit: 1000 } : { limit: 1000 });
        const keys = [];
        for (const k of (r.keys || [])) {
          if (!mirrorable(k.name)) continue;
          keys.push({ name: k.name, c: clockOf(k.metadata), exp: Number.isFinite(Number(k.expiration)) && Number(k.expiration) > 0 ? Number(k.expiration) : null });
        }
        return json({ keys, cursor: (r.list_complete === false && r.cursor) ? r.cursor : null });
      }
      const key = String(url.searchParams.get('key') || '');
      if (!mirrorable(key) || key.length > 300) return err('bad key');
      if (path === '/mirror/get' && method === 'GET') {
        const got = await getMeta(key, 'arrayBuffer');
        if (!present(got)) return err('no such key', 404);
        return new Response(got.value, { status: 200, headers: { 'Content-Type': 'application/octet-stream', 'x-lij-clock': String(clockOf(got.metadata)), ...CORS } });
      }
      const clock = Number(url.searchParams.get('clock'));
      if (!Number.isFinite(clock) || clock <= 0) return err('bad clock');
      if (path === '/mirror/put' && method === 'POST') {
        if (key.startsWith(TOMB_PREFIX)) return err('a tombstone is written by /mirror/delete');
        const cur = await getMeta(key, 'arrayBuffer');
        const stored = present(cur) ? new Uint8Array(cur.value) : null;
        if (stored && clockOf(cur.metadata) >= clock) return json({ ok: true, applied: false, reason: 'stored is as new or newer' });
        const tomb = await getMeta(TOMB_PREFIX + key);
        if (present(tomb) && clockOf(tomb.metadata) >= clock) return json({ ok: true, applied: false, reason: 'deleted later' });
        if (!recordAllows(key, bodyBytes, stored)) return json({ ok: true, applied: false, reason: 'the record rule' });
        const exp = Number(url.searchParams.get('expiration'));
        const opts = { metadata: { c: clock } };
        if (Number.isFinite(exp) && exp > 0) {
          if (exp < Date.now() / 1000 + 60) return json({ ok: true, applied: false, reason: 'expiring' });   // KV refuses an expiry under a minute away
          opts.expiration = Math.floor(exp);
        }
        await rawKv.put(key, bodyBytes, opts);
        return json({ ok: true, applied: true });
      }
      if (path === '/mirror/delete' && method === 'POST') {
        if (key.startsWith(TOMB_PREFIX)) return err('bad key');
        const cur = await getMeta(key, 'arrayBuffer');
        const has = present(cur);
        if (has && clockOf(cur.metadata) >= clock) return json({ ok: true, applied: false, reason: 'stored is as new or newer' });
        const tomb = await getMeta(TOMB_PREFIX + key);
        if (present(tomb) && clockOf(tomb.metadata) >= clock) return json({ ok: true, applied: false, reason: 'already' });
        if (has) await rawKv.delete(key);
        try { await rawKv.put(TOMB_PREFIX + key, '1', { expirationTtl: TOMB_TTL_S, metadata: { c: clock } }); } catch (_) {}
        return json({ ok: true, applied: true, existed: !!has });
      }
      return err('Not found', 404);
    }

    // ── Health check ─────────────────────────────────────────────────────────

    if (path === '/health' && method === 'GET') {
      return json({ ok: true, service: 'lij-worker', version: '0.18.0' });   // 0.8.0: filter_url / filter_sp · 0.9.0: /backup/meta · 0.10.0: the copy's fingerprint · 0.11.0: the tatara block (lijox-register:v3) · 0.12.0: the channel list its own · 0.12.1: close_sizes gone · 0.13.0: the routes list (lijox-register:v4) · 0.14.0: Kimi round 2 — the shape rules, the cursor, the per-nonce challenge, the freshness rules, the caps · 0.15.0: the signed name transfer (K1), cacheTtl 30 on the backup reads (K2), /lsps1/channel retired (K11) · 0.16.0: the per-address rate limit (K3/K8 — 60/min registry writes, 300/min the other writes) · 0.17.0: Phase C — the clock on every write, the tombstone on every delete, the signed /mirror/* routes for the box's door · 0.18.0: the push's proof binds the copy (lij-backup-v2 — K6a; v1 taken this one release) · 0.17.1: the lnurlp lookup's redirect mode 'manual' (Workers throws on 'error' — every lookup answered 502 from 0.14.0 to 0.17.0)
    }

    // ── LSP Registry ─────────────────────────────────────────────────────────

    if (path === '/lsps' && method === 'GET') {
      const names = await kvListAll(env, 'lsp:');   // 0.14.0 (K3): every page, read in bulk
      const got = await kvGetMany(env, names);
      const lsps = [];

      for (const name of names) {
        const raw = got.get(name);
        if (raw) {
          try {
            const rec = JSON.parse(raw);
            // S41: proofs get checked, not published. signature/ts are
            // write-time evidence for the registry, not wallet data — no
            // client reads them, and republishing a live proof invites
            // replay games inside the freshness window.
            delete rec.signature;
            delete rec.ts;
            // 0.6.0: liveness fields. registered_at is rewritten on every (re-)registration,
            // so it is "last seen"; stale = no registration for 24h. Wallets act on `stale`
            // only once adapters re-register on a cadence (0.71.0) — until then it is
            // informational.
            rec.last_seen_ms = rec.registered_at || null;
            rec.first_registered_at = rec.first_registered_at || rec.registered_at || null;
            rec.stale = rec.registered_at ? (Date.now() - rec.registered_at) > 24 * 3600 * 1000 : false;
            lsps.push(rec);
          } catch (_) {}
        }
      }

      // v371 VIABILITY GATE. Ranking used to be blind to whether a record
      // could function at all: no wss_url means no LN peer is possible from
      // an https origin, yet such a record sorted FIRST purely for being
      // cheap (uptime is a registration-time constant nothing ever revises).
      // Viability is now a ranking PRECONDITION. This refuses nobody and
      // deletes nothing — permissionless enrollment stands; records just
      // rank where their actual usability puts them. Price/uptime remains
      // the tiebreak WITHIN each class.
      const viable = (l) => !!(l && l.wss_url && !/^http:\/\//i.test(l.endpoint || ''));
      lsps.sort((a, b) => {
        const va = viable(a), vb = viable(b);
        if (va !== vb) return va ? -1 : 1;
        const scoreA = (a.fee_ppm * 0.6) + ((100 - (a.uptime || 0)) * 0.4);
        const scoreB = (b.fee_ppm * 0.6) + ((100 - (b.uptime || 0)) * 0.4);
        return scoreA - scoreB;
      });

      return json({ lsps });
    }

    if (path === '/lsps/register' && method === 'POST') {
      { const lim = await rateLimited(env, 'RL_REGISTER', request); if (lim) return lim; }   // 0.16.0: 60/min per address
      if (tooLarge(request, 16 * 1024)) return err('body exceeds the 16 KB cap', 413);   // 0.14.0 (K8)
      let body;
      try {
        body = await request.json();
      } catch (_) {
        return err('Invalid JSON');
      }

      // Phase 11: accept full LspInfo schema. Previously stripped 5 fields
      // (fee_base_sats, channel_open_fee_sats, max_channel_size_sats,
      // route_endpoint, route_macaroon) plus the new wss_url field.
      const {
        name, pubkey, endpoint, fee_ppm,
        fee_base_sats, channel_open_fee_sats, max_channel_size_sats,
        supports_jit, route_endpoint, route_macaroon, wss_url, signature, ts,
        filter_url, filter_sp, tatara, routes,
      } = body;

      if (!name || !pubkey || !endpoint || fee_ppm === undefined || !signature || ts === undefined) {
        return err('Missing required fields: name, pubkey, endpoint, fee_ppm, signature, ts');
      }

      // S41 register-signature fix (review #2): any POST could overwrite any
      // lsp:${pubkey}. Now the record is stored only if `signature` is a valid
      // LND signmessage by that pubkey over the FULL field set + a fresh ts.
      const pk = hexToBytes(pubkey);
      if (!pk || pk.length !== 33) {
        return err('pubkey must be 33-byte compressed hex');
      }
      if (!/^[0-9a-f]{66}$/.test(String(pubkey))) {
        return err('pubkey must be 66 lowercase hex');   // 0.14.0 (K10): one identity per key — an uppercase spelling made a second record nothing could unregister
      }
      const tsNum = Number(ts);
      if (!Number.isFinite(tsNum) || Math.abs(Date.now() / 1000 - tsNum) > 600) {
        return err('ts outside the 600s registration window', 403);
      }
      // 0.14.0 (K3): the stored fields have a shape — a name of at most 64 characters, plain https addresses of at most
      // 200 for endpoint and route_endpoint, a plain wss address for wss_url, a route token of at most 256 characters.
      // Refuses no LND registrant: an http endpoint cannot serve an https wallet page at all (mixed content).
      if (typeof name !== 'string' || name.length < 1 || name.length > 64) return err('name must be 1–64 characters');
      if (typeof endpoint !== 'string' || endpoint.length > 200 || endpoint.endsWith('/') || !FILTER_URL_RE.test(endpoint)) return err('endpoint must be a plain https:// address (a host, an optional :port and path, no trailing slash, 200 characters at most)');
      if (route_endpoint !== undefined && route_endpoint !== null && route_endpoint !== '' && (typeof route_endpoint !== 'string' || route_endpoint.length > 200 || route_endpoint.endsWith('/') || !FILTER_URL_RE.test(route_endpoint))) return err('route_endpoint must be a plain https:// address (200 characters at most)');
      if (wss_url !== undefined && wss_url !== null && wss_url !== '' && (typeof wss_url !== 'string' || wss_url.length > 200 || wss_url.endsWith('/') || !RELAY_URL_RE.test(wss_url))) return err('wss_url must be a plain wss:// address (200 characters at most)');
      if (route_macaroon !== undefined && route_macaroon !== null && (typeof route_macaroon !== 'string' || route_macaroon.length > 256)) return err('route_macaroon must be a string of at most 256 characters');
      // 0.8.0: the optional block-filter server (+ whether it serves the silent-payment index)
      const filterUrl = cleanFilterUrl(filter_url);
      if (filterUrl === undefined) {
        return err('filter_url must be a plain https:// address (a host, an optional :port and path, no trailing slash, 200 characters at most)');
      }
      // 0.11.0: the optional Tatara block (shape only; the wallets decide on the values)
      const tat = cleanTatara(tatara);
      if (tat === undefined) {
        return err('tatara block malformed (known keys only; whole numbers within bounds; sizes and channel sizes ascending; relay_url a plain wss:// address; coin_check_url a plain https:// address; ring_hash 64 lowercase hex)');
      }
      // 0.13.0: the optional routes list (shape only); its first route must repeat the record's own three addresses
      const rts = cleanRoutes(routes);
      if (rts === undefined) {
        return err('routes malformed (1–3 routes; each exactly {reach, endpoint, wss_url, filter_url}; reach direct|cloudflare|tor; endpoint a plain https:// address; wss_url a plain wss:// address; filter_url a plain https:// address or empty; no two routes with the same endpoint)');
      }
      if (rts && (rts[0].endpoint !== endpoint || rts[0].wss_url !== (wss_url || null) || rts[0].filter_url !== filterUrl)) {
        return err('routes[0] must repeat the record\'s endpoint, wss_url and filter_url (the operator\'s first choice is what older wallets read)');
      }

      const lsp = {
        name,
        pubkey,
        endpoint,
        fee_ppm: Number(fee_ppm),
        fee_base_sats: fee_base_sats !== undefined ? Number(fee_base_sats) : 0,
        channel_open_fee_sats: channel_open_fee_sats !== undefined ? Number(channel_open_fee_sats) : 0,
        max_channel_size_sats: max_channel_size_sats !== undefined ? Number(max_channel_size_sats) : 0,
        supports_jit: Boolean(supports_jit),
        route_endpoint: route_endpoint || null,
        route_macaroon: route_macaroon || null,
        wss_url: wss_url || null,
        filter_url: filterUrl,                              // 0.8.0: null = this provider offers none (wallets use the default)
        filter_sp: filterUrl ? Boolean(filter_sp) : false,  // 0.8.0: its server serves the silent-payment index (/sp/info)
        ...(tat ? { tatara: tat } : {}),                    // 0.11.0: present only when offered (v1/v2 records keep their shape)
        ...(rts ? { routes: rts } : {}),                    // 0.13.0: present only when sent (one-door records keep their shape)
        uptime: 100,
        registered_at: Date.now(),   // = last seen; adapters ≥0.71 re-register on a cadence
        ts: tsNum,
        signature,
      };
      // 0.6.0: keep the first registration time across re-registrations ("listed since").
      let prevTs = null;
      try {
        const prev = await env.LIJ_KV.get(`lsp:${pubkey}`);
        const prevRec = prev ? JSON.parse(prev) : null;
        lsp.first_registered_at = (prevRec && prevRec.first_registered_at) || (prevRec && prevRec.registered_at) || lsp.registered_at;
        if (prevRec && Number.isFinite(Number(prevRec.ts))) prevTs = Number(prevRec.ts);
      } catch (_) { lsp.first_registered_at = lsp.registered_at; }
      // 0.14.0 (K5): a captured registration cannot roll the record back — older than the stored one is refused (strict:
      // the adapter may register twice in one second); an unregister's tombstone (20 min) must be outdone too
      if (prevTs !== null && tsNum < prevTs) return err('older than the current record', 409);
      try {
        const gone = await env.LIJ_KV.get(`lspgone:${pubkey}`);
        if (gone !== null && Number.isFinite(Number(gone)) && tsNum <= Number(gone)) return err('older than this key\'s departure', 409);
      } catch (_) {}

      // Canonical is built from the COERCED record — the signature vouches for
      // exactly what will be stored and served, not for raw request bytes.
      const msg = canonicalRegisterMsg(lsp);
      const ok = await verifyLndSignedRegistration(pubkey, msg, signature);
      if (!ok) {
        return err('signature does not verify for this pubkey over the registered fields', 403);
      }

      await env.LIJ_KV.put(`lsp:${pubkey}`, JSON.stringify(lsp));
      return json({ ok: true, pubkey });
    }

    // ── 0.6.0: POST /lsps/unregister — a signed departure (lijox-unregister:v1) ──
    if (path === '/lsps/unregister' && method === 'POST') {
      { const lim = await rateLimited(env, 'RL_REGISTER', request); if (lim) return lim; }   // 0.16.0: 60/min per address
      if (tooLarge(request, 64 * 1024)) return err('body exceeds the 64 KB cap', 413);   // 0.14.0 (K8)
      let body;
      try { body = await request.json(); } catch (_) { return err('body must be JSON'); }
      const pubkey = String(body.pubkey || '').toLowerCase();
      const ts = body.ts, signature = body.signature;
      if (!pubkey || ts === undefined || !signature) return err('Missing required fields: pubkey, ts, signature');
      const tsNum = Number(ts);
      if (!Number.isFinite(tsNum) || Math.abs(Date.now() / 1000 - tsNum) > 600) {
        return err('ts outside the 600s window', 403);
      }
      const existing = await env.LIJ_KV.get(`lsp:${pubkey}`);
      if (!existing) return json({ ok: true, pubkey, removed: false });
      let rec = null;
      try { rec = JSON.parse(existing); } catch (_) {}
      if (rec && Number.isFinite(Number(rec.ts)) && tsNum <= Number(rec.ts)) {
        return err('unregister ts must be newer than the current registration', 403);
      }
      const ok = await verifyLndSignedRegistration(pubkey, canonicalUnregisterMsg(pubkey, tsNum), signature);
      if (!ok) return err('signature does not verify for this pubkey', 403);
      await env.LIJ_KV.delete(`lsp:${pubkey}`);
      try { await env.LIJ_KV.put(`lspgone:${pubkey}`, String(tsNum), { expirationTtl: 1200 }); } catch (_) {}   // 0.14.0 (K5): the tombstone a captured older registration cannot outdo
      return json({ ok: true, pubkey, removed: true });
    }

    // ── LSP SCB backup — signed by the node key (lijox-scb:v1) ──────────────
    if (path === '/lsp-backup' && (method === 'PUT' || method === 'GET')) {
      if (method === 'PUT') { const lim = await rateLimited(env, 'RL_WRITE', request); if (lim) return lim; }   // 0.16.0: 300/min per address (the GET is a read)
      const pubkey = String(request.headers.get('x-lij-pubkey') || '').toLowerCase();
      const ts = Number(request.headers.get('x-lij-ts'));
      const sig = request.headers.get('x-lij-sig') || '';
      const pk = hexToBytes(pubkey);
      if (!pk || pk.length !== 33) {
        return err('x-lij-pubkey must be 33-byte compressed hex');
      }
      if (!sig) return err('x-lij-sig required');
      if (!Number.isFinite(ts) || Math.abs(Date.now() / 1000 - ts) > 600) {
        return err('x-lij-ts outside the 600s window', 403);
      }

      if (method === 'PUT') {
        if (tooLarge(request, 5 * 1024 * 1024)) return err('body exceeds the 5MB cap', 413);   // 0.14.0 (K8): before the read
        const body = new Uint8Array(await request.arrayBuffer());
        if (!body.length) return err('empty body');
        if (body.length > 5 * 1024 * 1024) return err('body exceeds the 5MB cap', 413);
        const hash = await sha256HexOf(body);
        const ok = await verifyLndSignedRegistration(pubkey, canonicalScbPush(pubkey, ts, hash), sig);
        if (!ok) return err('signature does not verify for this pubkey over this blob', 403);
        // rotate current → prev, then store (latest + one generation kept)
        const cur = await env.LIJ_KV.get(`lspscb:${pubkey}`, 'arrayBuffer');
        const curMeta = await env.LIJ_KV.get(`lspscbmeta:${pubkey}`);
        // 0.14.0 (K9): the same copy again is an OK, never a rotation (a replay used to cost the real previous
        // generation); a push older than the stored copy is refused
        let meta = null; try { meta = curMeta ? JSON.parse(curMeta) : null; } catch (_) { meta = null; }
        if (meta && meta.sha256 === hash) return json({ ok: true, sha256: hash, size: body.length, repeat: true });
        if (meta && Number.isFinite(Number(meta.ts)) && ts <= Number(meta.ts)) return err('older than the stored copy', 409);
        if (cur) await env.LIJ_KV.put(`lspscb:${pubkey}:prev`, cur);
        if (curMeta) await env.LIJ_KV.put(`lspscbmeta:${pubkey}:prev`, curMeta);
        await env.LIJ_KV.put(`lspscb:${pubkey}`, body);
        await env.LIJ_KV.put(`lspscbmeta:${pubkey}`, JSON.stringify({ sha256: hash, size: body.length, ts, stored_at: Date.now() }));
        return json({ ok: true, sha256: hash, size: body.length });
      }

      // GET — the restore leg (?gen=prev for the previous generation)
      const ok = await verifyLndSignedRegistration(pubkey, canonicalScbGet(pubkey, ts), sig);
      if (!ok) return err('signature does not verify for this pubkey', 403);
      const which = url.searchParams.get('gen') === 'prev' ? ':prev' : '';
      const blob = await env.LIJ_KV.get(`lspscb:${pubkey}${which}`, 'arrayBuffer');
      if (!blob) return err('no backup stored for this pubkey', 404);
      let meta = {};
      try { meta = JSON.parse(await env.LIJ_KV.get(`lspscbmeta:${pubkey}${which}`) || '{}'); } catch (_) {}
      return new Response(blob, {
        status: 200,
        headers: {
          'Content-Type': 'application/octet-stream',
          'x-lij-sha256': meta.sha256 || '',
          'x-lij-stored-at': String(meta.stored_at || ''),
          ...CORS,
        },
      });
    }

    // ── LSPS1 Channel Request — proxy to adapter ─────────────────────────────
    // 0.15.0 (S63, Kimi round 2 K11 — DP "Remove it"): /lsps1/channel was a proxy to an adapter route that does not
    // exist; nothing could complete through it, and it carried the adapter secret on every try. Retired.
    if (path === '/lsps1/channel') {
      return json({ error: 'retired — the adapter has no /lsps1/channel; wallets open channels through LSPS2 (JIT) at their provider', retired_in: '0.15.0' }, 410);
    }

    // ── Wallet Backup (signed challenge-response, no shared token) ───────────

    // Issue a single-use nonce bound to the caller's portable pubkey.
    if (path === '/backup/challenge' && method === 'GET') {
      { const lim = await rateLimited(env, 'RL_WRITE', request); if (lim) return lim; }   // 0.16.0: 300/min per address
      const pubkey = url.searchParams.get('pubkey');
      const pkb = pubkey ? hexToBytes(pubkey) : null;
      if (!pkb || pkb.length !== 33) return err('Missing or invalid pubkey');   // 0.14.0 (K4): a 33-byte key — any even-length hex used to mint one
      const nonce = [...crypto.getRandomValues(new Uint8Array(32))]
        .map((b) => b.toString(16).padStart(2, '0'))
        .join('');
      // 120s TTL (KV minimum is 60s); single-use — deleted on successful verify. 0.14.0 (K4): one key per challenge.
      await env.LIJ_KV.put(`bkpchal:${pubkey}:${nonce}`, nonce, { expirationTtl: 120 });
      return json({ nonce, expires_in: 120 });
    }

    if (path === '/backup' && method === 'POST') {
      { const lim = await rateLimited(env, 'RL_WRITE', request); if (lim) return lim; }   // 0.16.0: 300/min per address
      if (tooLarge(request, 8 * 1024 * 1024)) return err('body exceeds the 8 MB cap', 413);   // 0.14.0 (K8)
      let body;
      try {
        body = await request.json();
      } catch (_) {
        return err('Invalid JSON');
      }

      const { pubkey_hex, nonce, signature, blob } = body;
      if (!pubkey_hex || !nonce || !signature || !blob) {
        return err('Missing pubkey_hex / nonce / signature / blob');
      }
      if (typeof blob !== 'object' || !Number.isSafeInteger(blob.version) || blob.version < 0) {
        return err('blob.version must be a whole number');   // 0.14.0 (K6b): an object or a missing number passed the `>=` check below and froze the copy
      }
      // 0.10.0 (S57, DP 2026-10-08 14:40 "Agreed on the fix for the cloud copy fingerprint. Go"): the copy's FINGERPRINT —
      // sha256 of its sealed bytes, the same the phone takes before it uploads — is kept with the copy and answered by
      // /backup/meta, so a phone can tell its own upload (the OK never arrived: the app was put away mid-upload) from
      // another copy's. A resend of the very same copy (same number, same fingerprint) is accepted again, not refused
      // as stale: the phone's retry after a lost OK is then an OK, never a false conflict.
      const fingerprint = await blobFingerprint(blob);
      // 0.18.0 (K6a): a v2 push's proof is checked over THIS copy's fingerprint and number; a copy that carries no byte
      // array has no fingerprint and cannot be bound — refused as a v2. A v1 push (no auth_v) is still taken this release.
      const authV = body.auth_v === undefined ? 1 : body.auth_v;
      if (authV !== 1 && authV !== 2) return err('auth_v must be 1 or 2');
      if (authV === 2 && !fingerprint) return err('a v2 push binds the copy\'s bytes — encrypted_data must be a byte array');
      if (!(await verifyBackupAuth(env, 'backup-push', pubkey_hex, nonce, signature, authV === 2 ? { fingerprint, version: blob.version } : null))) {
        return err('Invalid signature or expired challenge', 401);
      }
      if (blob.pubkey_hex !== pubkey_hex) {
        return err('blob pubkey_hex does not match authenticated pubkey', 400);
      }
      const existing = await env.LIJ_KV.get(`backup:${pubkey_hex}`, { cacheTtl: 30 });   // 0.15.0 (K2): the shortest edge cache — a write elsewhere shows within 30 s, not 60
      if (existing) {
        const prev = JSON.parse(existing);
        if (prev.version === blob.version && fingerprint && prev.fingerprint === fingerprint) {
          await env.LIJ_KV.delete(`bkpchal:${pubkey_hex}:${nonce}`);
          return json({ ok: true, version: blob.version, repeat: true, fingerprint });
        }
        if (prev.version >= blob.version) {
          return err(
            `Stale backup rejected: existing v${prev.version} >= incoming v${blob.version}`,
            409
          );
        }
      }

      await env.LIJ_KV.put(`backup:${pubkey_hex}`, JSON.stringify(fingerprint ? { ...blob, fingerprint } : blob));
      await env.LIJ_KV.delete(`bkpchal:${pubkey_hex}:${nonce}`);
      return json({ ok: true, version: blob.version, fingerprint });
    }

    // Authenticated read (POST so the signature travels in the body).
    if (path === '/backup/fetch' && method === 'POST') {
      { const lim = await rateLimited(env, 'RL_WRITE', request); if (lim) return lim; }   // 0.16.0: 300/min per address
      if (tooLarge(request, 64 * 1024)) return err('body exceeds the 64 KB cap', 413);   // 0.14.0 (K8)
      let body;
      try {
        body = await request.json();
      } catch (_) {
        return err('Invalid JSON');
      }

      const { pubkey_hex, nonce, signature } = body;
      if (!pubkey_hex || !nonce || !signature) {
        return err('Missing pubkey_hex / nonce / signature');
      }
      if (!(await verifyBackupAuth(env, 'backup-read', pubkey_hex, nonce, signature))) {
        return err('Invalid signature or expired challenge', 401);
      }
      await env.LIJ_KV.delete(`bkpchal:${pubkey_hex}:${nonce}`);

      const raw = await env.LIJ_KV.get(`backup:${pubkey_hex}`, { cacheTtl: 30 });   // 0.15.0 (K2)
      if (!raw) {
        return json({ found: false }, 404);
      }
      return json({ found: true, blob: JSON.parse(raw) });
    }

    // 0.9.0 (S57, DP 2026-10-07 "Go with … 1"): the cloud copy's NUMBER AND DATE only. Before a wallet connects to its
    // provider it compares the cloud's number with its own; a higher cloud number means another copy (or this phone
    // before a reload) saved after it. /backup/fetch would send the whole sealed copy (~1.4 MB) to the phone at every
    // unlock; this sends two numbers, read from the copy's unencrypted envelope. Same signed challenge as /backup/fetch
    // (action "backup-read"); 200 {found:false} when no copy is held — a 404 means only that the route is missing.
    if (path === '/backup/meta' && method === 'POST') {
      { const lim = await rateLimited(env, 'RL_WRITE', request); if (lim) return lim; }   // 0.16.0: 300/min per address
      if (tooLarge(request, 64 * 1024)) return err('body exceeds the 64 KB cap', 413);   // 0.14.0 (K8)
      let body;
      try {
        body = await request.json();
      } catch (_) {
        return err('Invalid JSON');
      }
      const { pubkey_hex, nonce, signature } = body;
      if (!pubkey_hex || !nonce || !signature) {
        return err('Missing pubkey_hex / nonce / signature');
      }
      if (!(await verifyBackupAuth(env, 'backup-read', pubkey_hex, nonce, signature))) {
        return err('Invalid signature or expired challenge', 401);
      }
      await env.LIJ_KV.delete(`bkpchal:${pubkey_hex}:${nonce}`);
      const raw = await env.LIJ_KV.get(`backup:${pubkey_hex}`, { cacheTtl: 30 });   // 0.15.0 (K2)
      if (!raw) return json({ found: false });
      let b = {};
      try { b = JSON.parse(raw) || {}; } catch (_) { b = {}; }
      // 0.10.0: the stored copy's fingerprint rides along (null for a copy stored before 0.10.0)
      const fp = (typeof b.fingerprint === 'string' && /^[0-9a-f]{64}$/.test(b.fingerprint)) ? b.fingerprint : null;
      return json({ found: true, version: Number(b.version) || 0, saved_at_ms: Number(b.saved_at_ms) || 0, fingerprint: fp });
    }

    // 0.7.0 (S46, DP GO 2026-09-13): the wallet forgets its own cloud copy — the same
    // signed challenge as push/read (action "backup-forget"), so only the key that
    // wrote the blob can delete it. Idempotent: deleting nothing is still ok:true.
    // (Erase on the phone is local-only; this is the other half — "off means off".)
    if (path === '/backup/forget' && method === 'POST') {
      { const lim = await rateLimited(env, 'RL_WRITE', request); if (lim) return lim; }   // 0.16.0: 300/min per address
      if (tooLarge(request, 64 * 1024)) return err('body exceeds the 64 KB cap', 413);   // 0.14.0 (K8)
      let body;
      try {
        body = await request.json();
      } catch (_) {
        return err('Invalid JSON');
      }
      const { pubkey_hex, nonce, signature } = body;
      if (!pubkey_hex || !nonce || !signature) {
        return err('Missing pubkey_hex / nonce / signature');
      }
      if (!(await verifyBackupAuth(env, 'backup-forget', pubkey_hex, nonce, signature))) {
        return err('Invalid signature or expired challenge', 401);
      }
      await env.LIJ_KV.delete(`bkpchal:${pubkey_hex}:${nonce}`);
      const existed = !!(await env.LIJ_KV.get(`backup:${pubkey_hex}`, { cacheTtl: 30 }));   // 0.15.0 (K2)
      await env.LIJ_KV.delete(`backup:${pubkey_hex}`);
      return json({ ok: true, existed });
    }

    // ── LND Proxy ─────────────────────────────────────────────────────────────
    // Removed in v0.2: route was never called by any client (wallet, adapter,
    // or otherwise). Dead code carried for ~2 months; auditors prefer it gone.
    // If you need to re-add: see git history for the original implementation.

    return err('Not found', 404);
  },
};
// Named exports for the local sign\xe2\x86\x94verify gate (test-register-sig.mjs).
// The Workers runtime uses only the default export; these are inert there.
export { canonicalRegisterMsg, canonicalUnregisterMsg, verifyLndSignedRegistration, zbase32Decode, canonicalScbPush, canonicalScbGet, cleanFilterUrl, cleanTatara, cleanRoutes, TATARA_FIELDS, ROUTE_REACH };
