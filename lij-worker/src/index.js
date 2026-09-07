// Lightning-in-a-Jar Worker
// Deployed at: lij-worker.dp-a95.workers.dev
// Future: api.lightninginajar.xyz
//
// Routes:
//   GET  /health              — health check
//   GET  /lsps                — list registered LSPs ranked by score
//   POST /lsps/register       — register an LSP node (lijox-register:v1 —
//                               LND-signed over the full field set, ±600s ts)
//   PUT  /lsp-backup          — LSP pushes its own channel.backup (SCB),
//                               node-key signed (lijox-scb:v1); GET restores
//   POST /backup              — push encrypted wallet state (auth required)
//   GET  /backup/:pubkey      — pull encrypted wallet state (auth required)

import * as secp from '@noble/secp256k1';

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

// Verify a server-issued nonce + secp256k1 signature for `action` over the
// digest. Single-use: the challenge is deleted on success by the caller.
async function verifyBackupAuth(env, action, pubkeyHex, nonce, sigHex) {
  if (!pubkeyHex || !nonce || !sigHex) return false;
  const stored = await env.LIJ_KV.get(`bkpchal:${pubkeyHex}`);
  if (!stored || stored !== nonce) return false;
  const digest = await backupDigest(action, nonce, pubkeyHex);
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
  return 'lijox-register:v1:' + fields.map(encodeURIComponent).join(':');
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
  async fetch(request, env) {
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
    const nameMsg = (kind, name, pk, ts) => 'lijox-name:v1:' + [kind, name, pk, String(Number(ts) || 0)].map(encodeURIComponent).join(':');
    const nameAuth = async (body, kind) => {
      const name = String(body && body.name || '').toLowerCase();
      const pk = String(body && body.lsp_pubkey || '').toLowerCase();
      const ts = Number(body && body.ts);
      if (!NAME_RE.test(name)) return { e: err('bad name') };
      const pkb = hexToBytes(pk); if (!pkb || pkb.length !== 33) return { e: err('bad lsp_pubkey') };
      if (!Number.isFinite(ts) || Math.abs(Date.now() / 1000 - ts) > 600) return { e: err('ts outside window', 403) };
      if (!(await env.LIJ_KV.get(`lsp:${pk}`))) return { e: err('unknown LSP', 403) };
      const ok = await verifyLndSignedRegistration(pk, nameMsg(kind, name, pk, ts), String(body.signature || ''));
      if (!ok) return { e: err('signature does not verify', 403) };
      return { name, pk };
    };
    if (path === '/names/claim' && method === 'POST') {
      let body; try { body = await request.json(); } catch (_) { return err('Invalid JSON'); }
      const a = await nameAuth(body, 'claim'); if (a.e) return a.e;
      const cur = await env.LIJ_KV.get(`name:${a.name}`, 'json');
      if (cur && cur.lsp_pubkey !== a.pk) return err('name taken', 409);
      if (!cur) await env.LIJ_KV.put(`name:${a.name}`, JSON.stringify({ lsp_pubkey: a.pk, claimed_at: Date.now() }));
      return json({ ok: true, name: a.name, lsp_pubkey: a.pk, existed: !!cur });
    }
    if (path === '/names/release' && method === 'POST') {
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
      try { up = await fetch(String(lsp.endpoint).replace(/\/+$/, '') + '/.well-known/lnurlp/' + name, { cf: { cacheTtl: 0 } }); }
      catch (_) { return json({ status: 'ERROR', reason: 'LSP unreachable' }, 502); }
      const text = await up.text();
      const out = new Response(text, { status: up.status, headers: { ...CORS, 'Content-Type': 'application/json', 'Cache-Control': 'public, max-age=60' } });
      if (up.status === 200) { try { await cache.put(cacheKey, out.clone()); } catch (_) {} }
      return out;
    }

    // ── Health check ─────────────────────────────────────────────────────────

    if (path === '/health' && method === 'GET') {
      return json({ ok: true, service: 'lij-worker' });
    }

    // ── LSP Registry ─────────────────────────────────────────────────────────

    if (path === '/lsps' && method === 'GET') {
      const keys = await env.LIJ_KV.list({ prefix: 'lsp:' });
      const lsps = [];

      for (const key of keys.keys) {
        const raw = await env.LIJ_KV.get(key.name);
        if (raw) {
          try {
            const rec = JSON.parse(raw);
            // S41: proofs get checked, not published. signature/ts are
            // write-time evidence for the registry, not wallet data — no
            // client reads them, and republishing a live proof invites
            // replay games inside the freshness window.
            delete rec.signature;
            delete rec.ts;
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
      const tsNum = Number(ts);
      if (!Number.isFinite(tsNum) || Math.abs(Date.now() / 1000 - tsNum) > 600) {
        return err('ts outside the 600s registration window', 403);
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
        uptime: 100,
        registered_at: Date.now(),
        ts: tsNum,
        signature,
      };

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

    // ── LSP SCB backup — signed by the node key (lijox-scb:v1) ──────────────
    if (path === '/lsp-backup' && (method === 'PUT' || method === 'GET')) {
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
        const body = new Uint8Array(await request.arrayBuffer());
        if (!body.length) return err('empty body');
        if (body.length > 5 * 1024 * 1024) return err('body exceeds the 5MB cap', 413);
        const hash = await sha256HexOf(body);
        const ok = await verifyLndSignedRegistration(pubkey, canonicalScbPush(pubkey, ts, hash), sig);
        if (!ok) return err('signature does not verify for this pubkey over this blob', 403);
        // rotate current → prev, then store (latest + one generation kept)
        const cur = await env.LIJ_KV.get(`lspscb:${pubkey}`, 'arrayBuffer');
        const curMeta = await env.LIJ_KV.get(`lspscbmeta:${pubkey}`);
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
    // Browser calls this; Worker forwards to the adapter with the secret header.
    // Keeps the adapter secret out of the browser.

    if (path === '/lsps1/channel' && method === 'POST') {
      let body;
      try {
        body = await request.json();
      } catch (_) {
        return err('Invalid JSON');
      }

      const adapterUrl = env.LIJ_ADAPTER_URL;
      const adapterSecret = env.LIJ_ADAPTER_SECRET;

      if (!adapterUrl || !adapterSecret) {
        return err('Adapter not configured', 503);
      }

      try {
        const adapterResponse = await fetch(`${adapterUrl}/lsps1/channel`, {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            'x-adapter-secret': adapterSecret,
          },
          body: JSON.stringify(body),
        });

        const data = await adapterResponse.json();
        return json(data, adapterResponse.status);
      } catch (e) {
        return err(`Adapter fetch failed: ${e.message}`, 502);
      }
    }

    // ── Wallet Backup (signed challenge-response, no shared token) ───────────

    // Issue a single-use nonce bound to the caller's portable pubkey.
    if (path === '/backup/challenge' && method === 'GET') {
      const pubkey = url.searchParams.get('pubkey');
      if (!pubkey || !hexToBytes(pubkey)) return err('Missing or invalid pubkey');
      const nonce = [...crypto.getRandomValues(new Uint8Array(32))]
        .map((b) => b.toString(16).padStart(2, '0'))
        .join('');
      // 120s TTL (KV minimum is 60s); single-use — deleted on successful verify.
      await env.LIJ_KV.put(`bkpchal:${pubkey}`, nonce, { expirationTtl: 120 });
      return json({ nonce, expires_in: 120 });
    }

    if (path === '/backup' && method === 'POST') {
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
      if (!(await verifyBackupAuth(env, 'backup-push', pubkey_hex, nonce, signature))) {
        return err('Invalid signature or expired challenge', 401);
      }
      if (blob.pubkey_hex !== pubkey_hex) {
        return err('blob pubkey_hex does not match authenticated pubkey', 400);
      }

      const existing = await env.LIJ_KV.get(`backup:${pubkey_hex}`);
      if (existing) {
        const prev = JSON.parse(existing);
        if (prev.version >= blob.version) {
          return err(
            `Stale backup rejected: existing v${prev.version} >= incoming v${blob.version}`,
            409
          );
        }
      }

      await env.LIJ_KV.put(`backup:${pubkey_hex}`, JSON.stringify(blob));
      await env.LIJ_KV.delete(`bkpchal:${pubkey_hex}`);
      return json({ ok: true, version: blob.version });
    }

    // Authenticated read (POST so the signature travels in the body).
    if (path === '/backup/fetch' && method === 'POST') {
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
      await env.LIJ_KV.delete(`bkpchal:${pubkey_hex}`);

      const raw = await env.LIJ_KV.get(`backup:${pubkey_hex}`);
      if (!raw) {
        return json({ found: false }, 404);
      }
      return json({ found: true, blob: JSON.parse(raw) });
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
export { canonicalRegisterMsg, verifyLndSignedRegistration, zbase32Decode, canonicalScbPush, canonicalScbGet };
