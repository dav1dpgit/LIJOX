// test-round5.mjs — lij-worker 0.17.0 (S63, Phase C — the two doors of one registry): the clock on every write, the
// tombstone on every delete, `bkpchal:` a door's own, and the signed /mirror/* routes the box's side drives.
// Run: node test-round5.mjs   (CI runs it before the deploy; a red here blocks)
import * as secp from '@noble/secp256k1';
import { createHmac, createHash, randomBytes } from 'node:crypto';
import worker from './src/index.js';
import { canonicalRegisterMsg, canonicalUnregisterMsg } from './src/index.js';
import { mirrorMsg, sha256Hex, TOMB_TTL_S } from './src/mirror.js';

secp.etc.hmacSha256Sync = (key, ...msgs) => { const h = createHmac('sha256', Buffer.from(key)); for (const m of msgs) h.update(Buffer.from(m)); return new Uint8Array(h.digest()); };
let fails = 0;
const ok = (m) => console.log('  ok · ' + m);
const check = (c, m, extra) => { if (!c) { fails++; console.log('FAIL · ' + m + (extra !== undefined ? ' — ' + JSON.stringify(extra).slice(0, 300) : '')); } else ok(m); };
const hex = (b) => Buffer.from(b).toString('hex');

// ── an in-memory KV with metadata and expiry (the shape Cloudflare's has) ──
function makeKv() {
  const store = new Map();   // name → { v: Uint8Array, meta, exp }
  const enc = (v) => typeof v === 'string' ? new TextEncoder().encode(v) : v instanceof Uint8Array ? v : new Uint8Array(v);
  const live = (name) => { const e = store.get(name); if (!e) return null; if (e.exp && e.exp <= Date.now() / 1000) { store.delete(name); return null; } return e; };
  const as = (e, type) => { if (!e) return null; if (type === 'arrayBuffer') return e.v.buffer.slice(e.v.byteOffset, e.v.byteOffset + e.v.byteLength); const t = new TextDecoder().decode(e.v); if (type === 'json') { try { return JSON.parse(t); } catch (_) { return null; } } return t; };
  const typeOf = (o) => (o && typeof o === 'object') ? o.type : o;
  const kv = {
    store,
    get: async (k, o) => { if (Array.isArray(k)) { const m = new Map(); for (const n of k) m.set(n, as(live(n), typeOf(o))); return m; } return as(live(k), typeOf(o)); },
    getWithMetadata: async (k, o) => { const e = live(k); return { value: as(e, typeOf(o)), metadata: e ? (e.meta || null) : null }; },
    put: async (k, v, o) => {
      const exp = o && o.expirationTtl ? Math.floor(Date.now() / 1000) + o.expirationTtl : (o && o.expiration ? o.expiration : null);
      if (exp && exp < Date.now() / 1000 + 60) throw new Error('expiration must be at least 60 s away');
      store.set(k, { v: enc(v), meta: (o && o.metadata) || null, exp });
    },
    delete: async (k) => { store.delete(k); },
    list: async (o) => { const all = [...store.keys()].filter((k) => k.startsWith((o && o.prefix) || '') && live(k)).sort(); return { keys: all.map((name) => ({ name, metadata: store.get(name).meta, expiration: store.get(name).exp || undefined })), list_complete: true }; },
  };
  return kv;
}
const kv = makeKv();
const boxPriv = secp.utils.randomPrivateKey(), boxPub = hex(secp.getPublicKey(boxPriv, true));
const env = { LIJ_KV: kv, LIJ_MIRROR_PUBKEY: boxPub };
const call = async (method, path, body, headers, e) => {
  const init = { method, headers: Object.assign({ 'Content-Type': 'application/json' }, headers || {}) };
  if (body !== undefined) init.body = typeof body === 'string' || body instanceof Uint8Array ? body : JSON.stringify(body);
  const r = await worker.fetch(new Request('https://lij-worker.test' + path, init), e || env, {});
  let j = null; try { j = await r.clone().json(); } catch (_) {}
  return { status: r.status, json: j, res: r };
};
const ZB32 = 'ybndrfg8ejkmcpqxot1uwisza345h769';
function zb32enc(bytes) { let bits = 0, acc = 0, out = ''; for (const b of bytes) { acc = (acc << 8) | b; bits += 8; while (bits >= 5) { bits -= 5; out += ZB32[(acc >>> bits) & 31]; } } if (bits > 0) out += ZB32[(acc << (5 - bits)) & 31]; return out; }
const dsha256 = (buf) => { const a = createHash('sha256').update(buf).digest(); return new Uint8Array(createHash('sha256').update(a).digest()); };
function lndSign(privKey, msg) { const digest = dsha256(Buffer.concat([Buffer.from('Lightning Signed Message:'), Buffer.from(msg, 'utf8')])); const sig = secp.sign(digest, privKey); const out = new Uint8Array(65); out[0] = 27 + 4 + sig.recovery; out.set(sig.toCompactRawBytes(), 1); return zb32enc(out); }
const nowS = () => Math.floor(Date.now() / 1000);
function keypair() { const priv = secp.utils.randomPrivateKey(); return { priv, pub: hex(secp.getPublicKey(priv, true)) }; }
function regBody(kp, ts) {
  const body = { name: 'LSP ' + kp.pub.slice(0, 6), pubkey: kp.pub, endpoint: 'https://lsp-' + kp.pub.slice(0, 6) + '.example', route_endpoint: 'https://lsp-' + kp.pub.slice(0, 6) + '.example', route_macaroon: 'tok' + kp.pub.slice(0, 8), wss_url: 'wss://lsp-' + kp.pub.slice(0, 6) + '.example/ws', fee_ppm: 250, supports_jit: true, ts: ts || nowS() };
  body.signature = lndSign(kp.priv, canonicalRegisterMsg(body));
  return body;
}
// the box's signed mirror call
async function mcall(method, pathAndQuery, body, opts) {
  const o = opts || {};
  const bytes = body === undefined ? new Uint8Array(0) : (body instanceof Uint8Array ? body : new TextEncoder().encode(typeof body === 'string' ? body : JSON.stringify(body)));
  const ts = o.ts !== undefined ? o.ts : nowS();
  const signedPath = o.signedPath !== undefined ? o.signedPath : pathAndQuery;
  const signedBytes = o.signedBytes !== undefined ? o.signedBytes : bytes;
  const digest = createHash('sha256').update(mirrorMsg(method, signedPath, ts, await sha256Hex(signedBytes))).digest();
  const sig = hex(secp.sign(digest, o.priv || boxPriv).toCompactRawBytes());
  const init = { method, headers: { 'x-lij-mirror-ts': String(ts), 'x-lij-mirror-sig': sig, 'Content-Type': 'application/octet-stream' } };
  if (method === 'POST') init.body = bytes;
  const r = await worker.fetch(new Request('https://lij-worker.test' + pathAndQuery, init), o.env || env, {});
  let j = null; try { j = await r.clone().json(); } catch (_) {}
  return { status: r.status, json: j, res: r };
}
const T0 = Date.now();

// ── the clock on every write ──
const A = keypair(), B = keypair();
let r = await call('POST', '/lsps/register', regBody(A));
check(r.status === 200, 'A registers', r.json);
let e = kv.store.get('lsp:' + A.pub);
check(e && e.meta && Number.isFinite(e.meta.c) && e.meta.c >= T0 && e.meta.c <= Date.now(), 'the registration carries the request\'s clock (metadata {c})', e && e.meta);
r = await call('GET', '/lsps');
check(r.status === 200 && r.json.lsps.length === 1 && r.json.lsps[0].pubkey === A.pub && !('signature' in r.json.lsps[0]), '/lsps answers as before (the clock is metadata, not record)', r.json);

// ── the tombstone on every delete; one clock per request ──
const uts = nowS() + 1;
r = await call('POST', '/lsps/unregister', { pubkey: A.pub, ts: uts, signature: lndSign(A.priv, canonicalUnregisterMsg(A.pub, uts)) });
check(r.status === 200 && r.json.removed === true, 'A unregisters', r.json);
const tomb = kv.store.get('tomb:lsp:' + A.pub), gone = kv.store.get('lspgone:' + A.pub);
check(tomb && tomb.meta && tomb.meta.c > 0 && tomb.exp && Math.abs(tomb.exp - (nowS() + TOMB_TTL_S)) <= 2, 'the unregister leaves tomb:lsp:<pk> with the clock and the 7-day expiry', tomb);
check(gone && gone.meta && gone.meta.c === tomb.meta.c, 'the lspgone put and the tombstone share the request\'s one clock', { gone: gone && gone.meta, tomb: tomb && tomb.meta });

// ── bkpchal: a door's own — no clock, no tombstone ──
const wpriv = randomBytes(32), wpub = hex(secp.getPublicKey(wpriv, true));
const digest = (action, nonce, pk) => createHash('sha256').update(Buffer.concat([Buffer.from('lij-backup-v1'), Buffer.from(action), Buffer.from(nonce, 'hex'), Buffer.from(pk, 'hex')])).digest();
const signedWith = (action, nonce) => ({ pubkey_hex: wpub, nonce, signature: hex(secp.sign(digest(action, nonce, wpub), wpriv).toCompactRawBytes()) });
const chal = async () => (await call('GET', '/backup/challenge?pubkey=' + wpub)).json.nonce;
let nonce = await chal();
e = kv.store.get('bkpchal:' + wpub + ':' + nonce);
check(e && !e.meta && e.exp, 'a challenge carries no clock (bkpchal: is never mirrored) and keeps its 120-s expiry', e);
r = await call('POST', '/backup', Object.assign(signedWith('backup-push', nonce), { blob: { pubkey_hex: wpub, version: 3, saved_at_ms: Date.now(), encrypted_data: [1, 2, 3] } }));
check(r.status === 200 && r.json.ok === true, 'a copy (v3) lands', r.json);
check(!kv.store.has('tomb:bkpchal:' + wpub + ':' + nonce), 'the challenge\'s delete leaves no tombstone', [...kv.store.keys()].filter((k) => k.startsWith('tomb:')));
const bk = kv.store.get('backup:' + wpub);
check(bk && bk.meta && bk.meta.c > 0, 'the copy carries the clock', bk && bk.meta);
r = await call('POST', '/backup/forget', signedWith('backup-forget', await chal()));
check(r.status === 200 && r.json.existed === true && kv.store.has('tomb:backup:' + wpub) && !kv.store.has('backup:' + wpub), 'forget deletes the copy and leaves tomb:backup:<pk>', r.json);

// ── the mirror routes: admission ──
r = await mcall('GET', '/mirror/keys', undefined, { env: { LIJ_KV: kv } });
check(r.status === 503 && /not configured/.test(r.json.error), 'no LIJ_MIRROR_PUBKEY → 503 "mirror not configured"', r.json);
r = await call('GET', '/mirror/keys');
check(r.status === 403, 'an unsigned call is refused (403)', r.json);
r = await mcall('GET', '/mirror/keys', undefined, { priv: secp.utils.randomPrivateKey() });
check(r.status === 403 && /signature/.test(r.json.error), 'another key\'s signature is refused', r.json);
r = await mcall('GET', '/mirror/keys', undefined, { ts: nowS() - 200 });
check(r.status === 403 && /ts outside/.test(r.json.error), 'a stale ts (−200 s) is refused', r.json);
r = await mcall('GET', '/mirror/get?key=lspgone:' + A.pub, undefined, { signedPath: '/mirror/get?key=lsp:' + B.pub });
check(r.status === 403 && /signature/.test(r.json.error), 'the path and query are inside the signed message — a swapped key does not verify', r.json);
r = await mcall('POST', '/mirror/put?key=name:zed&clock=' + (Date.now() + 5), new TextEncoder().encode('{"lsp_pubkey":"x"}'), { signedBytes: new TextEncoder().encode('{"lsp_pubkey":"y"}') });
check(r.status === 403 && /signature/.test(r.json.error), 'the body\'s hash is inside the signed message — a swapped body does not verify', r.json);

// ── the listing ──
r = await mcall('GET', '/mirror/keys');
const names = r.status === 200 ? r.json.keys.map((k) => k.name) : [];
check(r.status === 200 && names.includes('lspgone:' + A.pub) && names.includes('tomb:lsp:' + A.pub) && names.includes('tomb:backup:' + wpub) && !names.some((n) => n.startsWith('bkpchal:')) && r.json.cursor === null, '/mirror/keys lists every key with its clock but the challenges', names);
const goneRow = r.json.keys.find((k) => k.name === 'lspgone:' + A.pub);
check(goneRow && goneRow.c === gone.meta.c && Number.isFinite(goneRow.exp) && goneRow.exp > nowS(), 'a row carries c (the clock) and exp (unix s) when the key expires', goneRow);

// ── get / put / delete ──
r = await call('POST', '/lsps/register', regBody(B));
check(r.status === 200, 'B registers', r.json);
const bRow = kv.store.get('lsp:' + B.pub);
r = await mcall('GET', '/mirror/get?key=lsp:' + B.pub);
const got = r.status === 200 ? new Uint8Array(await r.res.arrayBuffer()) : null;
check(r.status === 200 && got && Buffer.from(got).equals(Buffer.from(bRow.v)) && r.res.headers.get('x-lij-clock') === String(bRow.meta.c), '/mirror/get hands the stored bytes with x-lij-clock', r.json);
r = await mcall('GET', '/mirror/get?key=lsp:' + 'ab'.repeat(33));
check(r.status === 404, '/mirror/get of an absent key is 404', r.json);
// a name put from the box, newer → applied; the same clock again → not applied (idempotent); older → not applied
const nameRec = JSON.stringify({ lsp_pubkey: B.pub, claimed_at: Date.now() });
const c1 = Date.now() + 10;
r = await mcall('POST', '/mirror/put?key=name:alice&clock=' + c1, nameRec);
e = kv.store.get('name:alice');
check(r.status === 200 && r.json.applied === true && e && new TextDecoder().decode(e.v) === nameRec && e.meta.c === c1, '/mirror/put stores the bytes with the clock it was handed', r.json);
r = await mcall('POST', '/mirror/put?key=name:alice&clock=' + c1, nameRec);
check(r.status === 200 && r.json.applied === false && /as new or newer/.test(r.json.reason), 'the same clock again (a replay) applies nothing', r.json);
r = await mcall('POST', '/mirror/put?key=name:alice&clock=' + (c1 - 1), '{"lsp_pubkey":"older"}');
check(r.status === 200 && r.json.applied === false && new TextDecoder().decode(kv.store.get('name:alice').v) === nameRec, 'an older clock applies nothing — the stored bytes stand', r.json);
r = await mcall('POST', '/mirror/put?key=name:alice&clock=' + (c1 + 1), '{"lsp_pubkey":"newer"}');
check(r.status === 200 && r.json.applied === true && new TextDecoder().decode(kv.store.get('name:alice').v) === '{"lsp_pubkey":"newer"}', 'a newer clock replaces', r.json);
globalThis.caches = { default: { match: async () => undefined, put: async () => {} } };   // the Workers cache the lnurlp route uses (as test-round2 does)
r = await call('GET', '/.well-known/lnurlp/zzz');   // the route exists; just the shape check — no upstream here
check(r.status === 404 || r.status === 503 || r.status === 502, 'the lnurlp lookup still runs for an unknown name', r.json);
// delete: a tombstone, then a put older than it is refused, a put newer than it lands
const c2 = c1 + 50;
r = await mcall('POST', '/mirror/delete?key=name:alice&clock=' + c2);
const t2 = kv.store.get('tomb:name:alice');
check(r.status === 200 && r.json.applied === true && r.json.existed === true && !kv.store.has('name:alice') && t2 && t2.meta.c === c2 && t2.exp, '/mirror/delete removes the key and leaves tomb:<key> with the clock', r.json);
r = await mcall('POST', '/mirror/delete?key=name:alice&clock=' + c2);
check(r.status === 200 && r.json.applied === false, 'the same delete again applies nothing', r.json);
r = await mcall('POST', '/mirror/put?key=name:alice&clock=' + (c2 - 1), nameRec);
check(r.status === 200 && r.json.applied === false && /deleted later/.test(r.json.reason) && !kv.store.has('name:alice'), 'a value older than the tombstone is refused ("deleted later")', r.json);
r = await mcall('POST', '/mirror/put?key=name:alice&clock=' + (c2 + 1), nameRec);
check(r.status === 200 && r.json.applied === true && kv.store.has('name:alice'), 'a value newer than the tombstone lands', r.json);
r = await mcall('POST', '/mirror/delete?key=name:alice&clock=' + (c2 - 5));
check(r.status === 200 && r.json.applied === false && kv.store.has('name:alice'), 'a delete older than the stored value applies nothing', r.json);
r = await mcall('POST', '/mirror/put?key=tomb:name:alice&clock=' + (c2 + 9), '1');
check(r.status === 400, 'a tombstone cannot be put — /mirror/delete writes those', r.json);
r = await mcall('POST', '/mirror/put?key=bkpchal:x:y&clock=' + (c2 + 9), 'n');
check(r.status === 400 && /bad key/.test(r.json.error), 'a challenge key is refused (never mirrored)', r.json);

// ── the record guards ──
const bOlder = regBody(B, nowS() - 100);   // a valid record with an older signed ts
r = await mcall('POST', '/mirror/put?key=lsp:' + B.pub + '&clock=' + (Date.now() + 100), JSON.stringify(Object.assign({}, bOlder, { registered_at: Date.now(), uptime: 100 })));
check(r.status === 200 && r.json.applied === false && /record rule/.test(r.json.reason), 'an lsp: record with an older signed ts is refused even under a newer clock (K5 holds across doors)', r.json);
const bNewer = regBody(B, nowS() + 5);
r = await mcall('POST', '/mirror/put?key=lsp:' + B.pub + '&clock=' + (Date.now() + 100), JSON.stringify(Object.assign({}, bNewer, { registered_at: Date.now(), uptime: 100 })));
check(r.status === 200 && r.json.applied === true, 'an lsp: record with a newer signed ts lands', r.json);
const copy = (v) => JSON.stringify({ pubkey_hex: wpub, version: v, saved_at_ms: Date.now(), encrypted_data: [v] });
const c3 = Date.now() + 200;
r = await mcall('POST', '/mirror/put?key=backup:' + wpub + '&clock=' + c3, copy(7));
check(r.status === 200 && r.json.applied === true, 'a copy v7 lands by the mirror (newer than the forget\'s tombstone)', r.json);
r = await mcall('POST', '/mirror/put?key=backup:' + wpub + '&clock=' + (c3 + 1), copy(6));
check(r.status === 200 && r.json.applied === false && /record rule/.test(r.json.reason), 'a copy with a lower number is refused even under a newer clock', r.json);
r = await mcall('POST', '/mirror/put?key=backup:' + wpub + '&clock=' + (c3 + 2), copy(8));
check(r.status === 200 && r.json.applied === true, 'a copy with a higher number lands', r.json);
r = await mcall('POST', '/mirror/put?key=lspgone:zz&clock=' + (c3 + 2) + '&expiration=' + (nowS() + 10), '1');
check(r.status === 200 && r.json.applied === false && /expiring/.test(r.json.reason), 'an expiration under a minute away is not written (KV would refuse it)', r.json);
r = await mcall('POST', '/mirror/put?key=lspgone:zz&clock=' + (c3 + 2) + '&expiration=' + (nowS() + 900), '1');
check(r.status === 200 && r.json.applied === true && kv.store.get('lspgone:zz').exp === nowS() + 900 || (r.json.applied === true && Math.abs(kv.store.get('lspgone:zz').exp - (nowS() + 900)) <= 1), 'an expiration travels with the put', r.json);

// ── the version ──
r = await call('GET', '/health'); check(/^0\.(1[7-9]|[2-9][0-9])\./.test(String(r.json.version)), 'the version on /health is 0.17.0 or later', r.json);

console.log(fails ? 'FAIL · test-round5 · ' + fails + ' failed' : 'PASS · test-round5 (Phase C: the clock, the tombstone, the mirror routes)');
process.exit(fails ? 1 : 0);
