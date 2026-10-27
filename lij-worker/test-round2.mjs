// test-round2.mjs — lij-worker 0.14.0 (S63, Kimi K3.1 Pro round 2): the registry's listing follows the KV cursor and
// reads in bulk; the registration's shape rules (name, endpoint, route_endpoint, wss_url, route_macaroon, lowercase
// pubkey, the 16 KB cap); the freshness rules (an older registration 409, the unregister tombstone); the backup
// challenge keyed by nonce (a 33-byte key); blob.version a whole number; the SCB repeat and the older-copy refusal;
// the lnurlp lookup's redirect:'error' and 64 KB cap; the content-length caps.
// Run: node test-round2.mjs   (CI runs it before the deploy; a red here blocks)
import * as secp from '@noble/secp256k1';
import { createHmac, createHash, randomBytes } from 'node:crypto';
import worker from './src/index.js';
import { canonicalRegisterMsg, canonicalUnregisterMsg, canonicalScbPush } from './src/index.js';

secp.etc.hmacSha256Sync = (key, ...msgs) => { const h = createHmac('sha256', Buffer.from(key)); for (const m of msgs) h.update(Buffer.from(m)); return new Uint8Array(h.digest()); };
let fails = 0;
const ok = (m) => console.log('  ok · ' + m);
const check = (c, m, extra) => { if (!c) { fails++; console.log('FAIL · ' + m + (extra !== undefined ? ' — ' + JSON.stringify(extra).slice(0, 300) : '')); } else ok(m); };
const hex = (b) => Buffer.from(b).toString('hex');

// ── an in-memory KV with paging (2 keys a page) and the bulk get (a Map), as Cloudflare's ──
const store = new Map();
const kv = {
  get: async (k, type) => {
    if (Array.isArray(k)) { const m = new Map(); for (const n of k) m.set(n, store.has(n) ? store.get(n) : null); return m; }
    if (!store.has(k)) return null;
    const v = store.get(k);
    if (type === 'json') { try { return JSON.parse(v); } catch (e) { return null; } }
    if (type === 'arrayBuffer') return v;
    return v;
  },
  put: async (k, v) => { store.set(k, v); },
  delete: async (k) => { store.delete(k); },
  list: async (o) => {
    const all = [...store.keys()].filter((k) => k.startsWith(o.prefix || '')).sort();
    const start = o.cursor ? Number(o.cursor) : 0;
    const page = all.slice(start, start + 2);
    const done = start + 2 >= all.length;
    return { keys: page.map((name) => ({ name })), list_complete: done, cursor: done ? undefined : String(start + 2) };
  },
};
const env = { LIJ_KV: kv };
const call = async (method, path, body, headers) => {
  const init = { method, headers: Object.assign({ 'Content-Type': 'application/json' }, headers || {}) };
  if (body !== undefined) init.body = typeof body === 'string' || body instanceof Uint8Array ? body : JSON.stringify(body);
  const r = await worker.fetch(new Request('https://lij-worker.test' + path, init), env, {});
  let j = null; try { j = await r.clone().json(); } catch (e) {}
  return { status: r.status, json: j, res: r };
};

// ── LND signmessage, as test-register-sig.mjs ──
const ZB32 = 'ybndrfg8ejkmcpqxot1uwisza345h769';
function zb32enc(bytes) { let bits = 0, acc = 0, out = ''; for (const b of bytes) { acc = (acc << 8) | b; bits += 8; while (bits >= 5) { bits -= 5; out += ZB32[(acc >>> bits) & 31]; } } if (bits > 0) out += ZB32[(acc << (5 - bits)) & 31]; return out; }
const dsha256 = (buf) => { const a = createHash('sha256').update(buf).digest(); return new Uint8Array(createHash('sha256').update(a).digest()); };
function lndSign(privKey, msg) { const digest = dsha256(Buffer.concat([Buffer.from('Lightning Signed Message:'), Buffer.from(msg, 'utf8')])); const sig = secp.sign(digest, privKey); const out = new Uint8Array(65); out[0] = 27 + 4 + sig.recovery; out.set(sig.toCompactRawBytes(), 1); return zb32enc(out); }
const nowS = () => Math.floor(Date.now() / 1000);
function keypair() { const priv = secp.utils.randomPrivateKey(); return { priv, pub: hex(secp.getPublicKey(priv, true)) }; }
function regBody(kp, over) {
  const body = Object.assign({ name: 'LSP ' + kp.pub.slice(0, 6), pubkey: kp.pub, endpoint: 'https://lsp-' + kp.pub.slice(0, 6) + '.example', route_endpoint: 'https://lsp-' + kp.pub.slice(0, 6) + '.example', route_macaroon: 'tok' + kp.pub.slice(0, 8), wss_url: 'wss://lsp-' + kp.pub.slice(0, 6) + '.example/ws', fee_ppm: 250, supports_jit: true, ts: nowS() }, over || {});
  body.signature = lndSign(kp.priv, canonicalRegisterMsg(body));
  return body;
}

// ── K3: the listing follows the cursor and reads in bulk ──
const kps = [];
for (let i = 0; i < 5; i++) { const kp = keypair(); kps.push(kp); const r = await call('POST', '/lsps/register', regBody(kp)); check(r.status === 200 && r.json.ok === true, 'r' + i + ' a signed registration lands (200)', r.json); }
let r = await call('GET', '/lsps');
check(r.status === 200 && Array.isArray(r.json.lsps) && r.json.lsps.length === 5, 'K3 /lsps lists all five across three KV pages (the cursor followed)', r.json && r.json.lsps && r.json.lsps.length);
check(r.json.lsps.every((l) => l.signature === undefined && l.ts === undefined), 'K3 the proofs are not published');

// ── K3: the shape rules ──
const kp = keypair();
r = await call('POST', '/lsps/register', regBody(kp, { name: 'x'.repeat(65) }));
check(r.status === 400 && /name/.test(r.json.error), 'K3 a 65-character name is refused (400)', r.json);
r = await call('POST', '/lsps/register', regBody(kp, { endpoint: 'http://plain.example' }));
check(r.status === 400 && /endpoint/.test(r.json.error), 'K3 an http:// endpoint is refused (an https wallet page cannot reach it)', r.json);
r = await call('POST', '/lsps/register', regBody(kp, { endpoint: 'https://' + 'a'.repeat(200) + '.example' }));
check(r.status === 400, 'K3 an endpoint over 200 characters is refused');
r = await call('POST', '/lsps/register', regBody(kp, { wss_url: 'ws://plain.example/ws' }));
check(r.status === 400 && /wss_url/.test(r.json.error), 'K3 a ws:// wss_url is refused', r.json);
r = await call('POST', '/lsps/register', regBody(kp, { route_endpoint: 'javascript:alert(1)' }));
check(r.status === 400 && /route_endpoint/.test(r.json.error), 'K3 a non-https route_endpoint is refused', r.json);
r = await call('POST', '/lsps/register', regBody(kp, { route_macaroon: 'm'.repeat(257) }));
check(r.status === 400 && /route_macaroon/.test(r.json.error), 'K3 a 257-character route token is refused', r.json);
r = await call('POST', '/lsps/register', regBody(kp, { pubkey: kp.pub.toUpperCase() }));
check(r.status === 400 && /lowercase/.test(r.json.error), 'K10 an uppercase pubkey is refused (one identity per key)', r.json);
r = await call('POST', '/lsps/register', JSON.stringify(regBody(kp)), { 'content-length': String(20 * 1024) });
check(r.status === 413, 'K8 a registration declaring 20 KB is refused before the read (413)', r.status);
r = await call('POST', '/lsps/register', regBody(kp, { name: 'Plotzwerks LSP-1', route_endpoint: undefined, route_macaroon: undefined }));
check(r.status === 200, 'K3 a real registration (a name with a space, no route fields) still lands', r.json);

// ── K5: freshness ──
const t0 = nowS();
r = await call('POST', '/lsps/register', regBody(kp, { ts: t0 + 5 }));
check(r.status === 200, 'K5 a newer registration lands');
r = await call('POST', '/lsps/register', regBody(kp, { ts: t0 + 2 }));
check(r.status === 409 && /older/.test(r.json.error), 'K5 a captured older registration is refused (409)', r.json);
r = await call('POST', '/lsps/register', regBody(kp, { ts: t0 + 5 }));
check(r.status === 200, 'K5 the same second again is fine (the adapter registers twice at boot)');
const unreg = { pubkey: kp.pub, ts: t0 + 9 }; unreg.signature = lndSign(kp.priv, canonicalUnregisterMsg(kp.pub, unreg.ts));
r = await call('POST', '/lsps/unregister', unreg);
check(r.status === 200 && r.json.removed === true && store.get('lspgone:' + kp.pub) === String(t0 + 9), 'K5 the unregister leaves its tombstone', r.json);
r = await call('POST', '/lsps/register', regBody(kp, { ts: t0 + 7 }));
check(r.status === 409 && /departure/.test(r.json.error), 'K5 a captured registration older than the departure is refused', r.json);
r = await call('POST', '/lsps/register', regBody(kp, { ts: t0 + 12 }));
check(r.status === 200, 'K5 a newer registration after the departure lands');

// ── K4: the backup challenge per nonce; a 33-byte key ──
const wpriv = randomBytes(32), wpub = hex(secp.getPublicKey(wpriv, true));
r = await call('GET', '/backup/challenge?pubkey=abcd');
check(r.status === 400, 'K4 a two-byte "pubkey" mints no challenge', r.json);
const c1 = await call('GET', '/backup/challenge?pubkey=' + wpub);
const c2 = await call('GET', '/backup/challenge?pubkey=' + wpub);
check(c1.status === 200 && c2.status === 200 && c1.json.nonce !== c2.json.nonce && store.has('bkpchal:' + wpub + ':' + c1.json.nonce) && store.has('bkpchal:' + wpub + ':' + c2.json.nonce), 'K4 two challenges live side by side — a second ask no longer wipes the first');
const digest = (action, nonce, pk) => createHash('sha256').update(Buffer.concat([Buffer.from('lij-backup-v1'), Buffer.from(action), Buffer.from(nonce, 'hex'), Buffer.from(pk, 'hex')])).digest();
const signedWith = (action, nonce) => ({ pubkey_hex: wpub, nonce, signature: hex(secp.sign(digest(action, nonce, wpub), wpriv).toCompactRawBytes()) });
r = await call('POST', '/backup', Object.assign(signedWith('backup-push', c1.json.nonce), { blob: { pubkey_hex: wpub, version: 3, saved_at_ms: Date.now(), encrypted_data: [1, 2, 3] } }));
check(r.status === 200 && r.json.ok === true && !store.has('bkpchal:' + wpub + ':' + c1.json.nonce) && store.has('bkpchal:' + wpub + ':' + c2.json.nonce), 'K4 the first challenge spends and is deleted; the second still stands', r.json);
r = await call('POST', '/backup', Object.assign(signedWith('backup-push', c1.json.nonce), { blob: { pubkey_hex: wpub, version: 4, encrypted_data: [1] } }));
check(r.status === 401, 'K4 a spent challenge is refused');
// ── K6b: blob.version a whole number ──
r = await call('POST', '/backup', Object.assign(signedWith('backup-push', c2.json.nonce), { blob: { pubkey_hex: wpub, version: { gt: 1 }, encrypted_data: [1] } }));
check(r.status === 400 && /version/.test(r.json.error) && store.has('bkpchal:' + wpub + ':' + c2.json.nonce), 'K6b a version that is an object is refused before the challenge is spent', r.json);
r = await call('POST', '/backup', Object.assign(signedWith('backup-push', c2.json.nonce), { blob: { pubkey_hex: wpub, version: 2, encrypted_data: [1] } }));
check(r.status === 409, 'K6b a lower whole number is still the old 409');
r = await call('POST', '/backup', JSON.stringify({ pubkey_hex: wpub, nonce: c2.json.nonce, signature: 'x', blob: {} }), { 'content-length': String(9 * 1024 * 1024) });
check(r.status === 413, 'K8 a backup push declaring 9 MB is refused before the read');

// ── K9: the SCB ──
const lp = keypair(); await call('POST', '/lsps/register', regBody(lp));
const scbPut = async (bytes, ts) => { const h = createHash('sha256').update(bytes).digest('hex'); return call('PUT', '/lsp-backup', bytes, { 'x-lij-pubkey': lp.pub, 'x-lij-ts': String(ts), 'x-lij-sig': lndSign(lp.priv, canonicalScbPush(lp.pub, ts, h)) }); };
const blobA = new Uint8Array([1, 2, 3, 4]), blobB = new Uint8Array([5, 6, 7, 8]);
const ts1 = nowS();
r = await scbPut(blobA, ts1); check(r.status === 200 && r.json.ok === true && !r.json.repeat, 'K9 the first SCB lands', r.json);
r = await scbPut(blobB, ts1 + 2); check(r.status === 200 && !r.json.repeat && store.has('lspscb:' + lp.pub + ':prev'), 'K9 a newer SCB rotates the first to prev');
r = await scbPut(blobB, ts1 + 4); check(r.status === 200 && r.json.repeat === true && Buffer.from(store.get('lspscb:' + lp.pub + ':prev')).equals(Buffer.from(blobA)), 'K9 the same copy again: repeat:true, the previous generation untouched', r.json);
r = await scbPut(blobA, ts1 + 1); check(r.status === 409 && /older/.test(r.json.error), 'K9 a captured older push is refused (409)', r.json);
r = await call('PUT', '/lsp-backup', blobA, { 'x-lij-pubkey': lp.pub, 'x-lij-ts': String(ts1), 'x-lij-sig': 'x', 'content-length': String(6 * 1024 * 1024) });
check(r.status === 413, 'K8 an SCB declaring 6 MB is refused before the read');

// ── K7: the lnurlp lookup — no redirect, 64 KB at most ──
globalThis.caches = { default: { match: async () => undefined, put: async () => {} } };
const lsp7 = keypair(); await call('POST', '/lsps/register', regBody(lsp7, { endpoint: 'https://lsp7.example' }));
const nm = { name: 'alice', lsp_pubkey: lsp7.pub, ts: nowS() }; nm.signature = lndSign(lsp7.priv, 'lijox-name:v1:' + ['claim', nm.name, nm.lsp_pubkey, String(nm.ts)].map(encodeURIComponent).join(':'));
r = await call('POST', '/names/claim', nm); check(r.status === 200 && r.json.ok === true, 'K7 the name is claimed', r.json);
let fetchInit = null;
// 0.17.1: the stub refuses what the Workers runtime refuses — `redirect: 'error'` is a TypeError before any request is
// sent (0.14.0–0.17.0 answered 502 to every lookup on Cloudflare for it; Node implements the mode, so a plain stub lied)
const workersFetch = (answer) => async (u, init) => { fetchInit = init; if (init && init.redirect === 'error') throw new TypeError("The 'redirect' field on 'RequestInitializerDict' is not implemented: 'error'"); return answer(u, init); };
globalThis.fetch = workersFetch(async () => new Response(JSON.stringify({ tag: 'payRequest', callback: 'https://lsp7.example/cb' }), { status: 200, headers: { 'Content-Type': 'application/json' } }));
r = await call('GET', '/.well-known/lnurlp/alice');
check(r.status === 200 && r.json.tag === 'payRequest' && fetchInit && fetchInit.redirect === 'manual', 'K7 the lookup passes the provider\'s answer through under the Workers runtime\'s redirect modes (manual) — 0.17.1', { status: r.status, redirect: fetchInit && fetchInit.redirect });
globalThis.fetch = workersFetch(async () => new Response('', { status: 302, headers: { Location: 'https://elsewhere.example/x' } }));
r = await call('GET', '/.well-known/lnurlp/alice');
check(r.status === 502 && /unreachable/.test(r.json.reason), 'K7 a redirect from the provider is refused (502), never followed', r.json);
globalThis.fetch = async () => new Response('x'.repeat(70 * 1024), { status: 200 });
r = await call('GET', '/.well-known/lnurlp/alice');
check(r.status === 502 && /too large/.test(r.json.reason), 'K7 a 70 KB answer is refused (502), not relayed', r.json);

// ── the version ──
r = await call('GET', '/health'); check(/^0\.(1[4-9]|[2-9][0-9])\./.test(String(r.json.version)), 'the version on /health is 0.14.0 or later', r.json);

console.log(fails ? 'FAIL · test-round2 · ' + fails + ' failed' : 'PASS · test-round2 (K3 K4 K5 K6b K7 K8 K9 K10)');
process.exit(fails ? 1 : 0);
