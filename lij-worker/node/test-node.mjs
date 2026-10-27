// node/test-node.mjs — lij-registry (Phase C, S63): the worker's code under Node with the file store, end to end over
// HTTP, and the two doors converging through the mirror (phase-c-r1 §6.1: "the port and the worker answer the same
// bytes for the same requests"; §6.2: the export is the first cycle).
// Run: node node/test-node.mjs   (from lij-worker/; CI runs it before the deploy; a red here blocks)
import * as secp from '@noble/secp256k1';
import { createHmac, createHash, randomBytes } from 'node:crypto';
import { promises as fs } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import http from 'node:http';
import worker from '../src/index.js';
import { canonicalRegisterMsg, canonicalUnregisterMsg, canonicalScbPush, canonicalScbGet } from '../src/index.js';
import { startRegistry, nodeHandler, memCache, clientAddress } from './server.js';
import { FileStore } from './store.js';
import { TOMB_TTL_S } from '../src/mirror.js';

secp.etc.hmacSha256Sync = (key, ...msgs) => { const h = createHmac('sha256', Buffer.from(key)); for (const m of msgs) h.update(Buffer.from(m)); return new Uint8Array(h.digest()); };
let fails = 0;
const ok = (m) => console.log('  ok · ' + m);
const check = (c, m, extra) => { if (!c) { fails++; console.log('FAIL · ' + m + (extra !== undefined ? ' — ' + JSON.stringify(extra).slice(0, 300) : '')); } else ok(m); };
const hex = (b) => Buffer.from(b).toString('hex');
const nowS = () => Math.floor(Date.now() / 1000);
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

// ── the in-memory KV with metadata and expiry (the Cloudflare door's store, as test-round5 has it) ──
function makeKv() {
  const store = new Map();
  const enc = (v) => typeof v === 'string' ? new TextEncoder().encode(v) : v instanceof Uint8Array ? v : new Uint8Array(v);
  const live = (name) => { const e = store.get(name); if (!e) return null; if (e.exp && e.exp <= Date.now() / 1000) { store.delete(name); return null; } return e; };
  const as = (e, type) => { if (!e) return null; if (type === 'arrayBuffer') return e.v.buffer.slice(e.v.byteOffset, e.v.byteOffset + e.v.byteLength); const t = new TextDecoder().decode(e.v); if (type === 'json') { try { return JSON.parse(t); } catch (_) { return null; } } return t; };
  const typeOf = (o) => (o && typeof o === 'object') ? o.type : o;
  return {
    store,
    get: async (k, o) => { if (Array.isArray(k)) { const m = new Map(); for (const n of k) m.set(n, as(live(n), typeOf(o))); return m; } return as(live(k), typeOf(o)); },
    getWithMetadata: async (k, o) => { const e = live(k); return { value: as(e, typeOf(o)), metadata: e ? (e.meta || null) : null }; },
    put: async (k, v, o) => { const exp = o && o.expirationTtl ? Math.floor(Date.now() / 1000) + o.expirationTtl : (o && o.expiration ? o.expiration : null); if (exp && exp < Date.now() / 1000 + 60) throw new Error('expiration must be at least 60 s away'); store.set(k, { v: enc(v), meta: (o && o.metadata) || null, exp }); },
    delete: async (k) => { store.delete(k); },
    list: async (o) => { const all = [...store.keys()].filter((k) => k.startsWith((o && o.prefix) || '') && live(k)).sort(); return { keys: all.map((name) => ({ name, metadata: store.get(name).meta, expiration: store.get(name).exp || undefined })), list_complete: true }; },
  };
}

// ── keys, signatures, bodies (as the other gates build them) ──
const ZB32 = 'ybndrfg8ejkmcpqxot1uwisza345h769';
function zb32enc(bytes) { let bits = 0, acc = 0, out = ''; for (const b of bytes) { acc = (acc << 8) | b; bits += 8; while (bits >= 5) { bits -= 5; out += ZB32[(acc >>> bits) & 31]; } } if (bits > 0) out += ZB32[(acc << (5 - bits)) & 31]; return out; }
const dsha256 = (buf) => { const a = createHash('sha256').update(buf).digest(); return new Uint8Array(createHash('sha256').update(a).digest()); };
function lndSign(privKey, msg) { const digest = dsha256(Buffer.concat([Buffer.from('Lightning Signed Message:'), Buffer.from(msg, 'utf8')])); const sig = secp.sign(digest, privKey); const out = new Uint8Array(65); out[0] = 27 + 4 + sig.recovery; out.set(sig.toCompactRawBytes(), 1); return zb32enc(out); }
function keypair() { const priv = secp.utils.randomPrivateKey(); return { priv, pub: hex(secp.getPublicKey(priv, true)) }; }
function regBody(kp, ts) {
  const body = { name: 'LSP ' + kp.pub.slice(0, 6), pubkey: kp.pub, endpoint: 'https://lsp-' + kp.pub.slice(0, 6) + '.example', route_endpoint: 'https://lsp-' + kp.pub.slice(0, 6) + '.example', route_macaroon: 'tok' + kp.pub.slice(0, 8), wss_url: 'wss://lsp-' + kp.pub.slice(0, 6) + '.example/ws', fee_ppm: 250, supports_jit: true, ts: ts || nowS() };
  body.signature = lndSign(kp.priv, canonicalRegisterMsg(body));
  return body;
}
const nameMsg = (kind, name, pk, ts) => 'lijox-name:v1:' + [kind, name, pk, String(ts)].map(encodeURIComponent).join(':');
const nameOp = (kp, kind, name) => { const ts = nowS(); const b = { name, lsp_pubkey: kp.pub, ts }; b.signature = lndSign(kp.priv, nameMsg(kind, name, kp.pub, ts)); return b; };
const wpriv = randomBytes(32), wpub = hex(secp.getPublicKey(wpriv, true));
const bdigest = (action, nonce, pk) => createHash('sha256').update(Buffer.concat([Buffer.from('lij-backup-v1'), Buffer.from(action), Buffer.from(nonce, 'hex'), Buffer.from(pk, 'hex')])).digest();
const signedWith = (action, nonce) => ({ pubkey_hex: wpub, nonce, signature: hex(secp.sign(bdigest(action, nonce, wpub), wpriv).toCompactRawBytes()) });
const copy = (v, bytes) => ({ pubkey_hex: wpub, version: v, saved_at_ms: Date.now(), encrypted_data: bytes || [v, v, v] });

// ── the two doors and the stub provider ──
const root = await fs.mkdtemp(path.join(os.tmpdir(), 'lij-registry-test-'));
const boxDir = path.join(root, 'box'), box2Dir = path.join(root, 'box2');
const boxPriv = secp.utils.randomPrivateKey(), boxPub = hex(secp.getPublicKey(boxPriv, true));
await fs.mkdir(boxDir, { recursive: true }); await fs.writeFile(path.join(boxDir, 'mirror.key'), hex(boxPriv) + '\n', { mode: 0o600 });
await fs.mkdir(box2Dir, { recursive: true }); await fs.writeFile(path.join(box2Dir, 'mirror.key'), hex(boxPriv) + '\n', { mode: 0o600 });
const lines = [];
const log = (l) => lines.push(l);
globalThis.caches = { default: memCache() };
const wkv = makeKv();
const W = http.createServer(nodeHandler({ fetchFn: worker.fetch, env: { LIJ_KV: wkv, LIJ_MIRROR_PUBKEY: boxPub }, host: 'lij-worker.test' }));
await new Promise((r) => W.listen(0, '127.0.0.1', r));
const WURL = 'http://127.0.0.1:' + W.address().port;
let stubHits = 0;
const stub = http.createServer((req, res) => { stubHits++; res.writeHead(200, { 'Content-Type': 'application/json' }); res.end(JSON.stringify({ status: 'OK', tag: 'payRequest', callback: 'https://lsp.example/cb', hits: stubHits })); });
await new Promise((r) => stub.listen(0, '127.0.0.1', r));
const STUB = 'http://127.0.0.1:' + stub.address().port;
const realFetch = globalThis.fetch;
globalThis.fetch = (url, init) => { const u = String(url); if (/^https:\/\/lsp-[0-9a-f]{6}\.example\//.test(u)) return realFetch(STUB + new URL(u).pathname, init); return realFetch(url, init); };
const reg = await startRegistry({ dir: boxDir, port: 0, host: 'registry.test', mirrorUrl: WURL, mirrorFirstDelayMs: 1e9, rlRegister: 3, rlWrite: 300, bodyCap: 100 * 1024, log });
const BURL = 'http://127.0.0.1:' + reg.port;
check(lines.some((l) => /mirror pubkey [0-9a-f]{66}/.test(l)) && reg.pubHex === boxPub, 'the box prints its mirror pubkey at boot (the key file read, not regenerated)', lines);
const call = async (base, method, p, body, headers) => {
  const init = { method, headers: Object.assign({ 'content-type': 'application/json' }, headers || {}) };
  if (body !== undefined) init.body = typeof body === 'string' || Buffer.isBuffer(body) || body instanceof Uint8Array ? body : JSON.stringify(body);
  const r = await realFetch(base + p, init);
  let j = null; const text = await r.text(); try { j = JSON.parse(text); } catch (_) {}
  return { status: r.status, json: j, text, headers: r.headers };
};
const B = (m, p, b, h) => call(BURL, m, p, b, h), Wc = (m, p, b, h) => call(WURL, m, p, b, h);

// ── the port, over HTTP ──
let r = await B('GET', '/health');
check(r.status === 200 && /^0\.(1[7-9]|[2-9][0-9])\./.test(String(r.json.version)) && r.headers.get('access-control-allow-origin') === '*' && r.headers.get('cache-control') === 'no-store', 'the box answers /health as the worker does (version 0.17.0 or later, CORS, no-store)', r.json);
const A = keypair(), C = keypair();
r = await B('POST', '/lsps/register', regBody(A));
check(r.status === 200 && r.json.ok === true, 'a registration lands on the box', r.json);
let e = await reg.store.getWithMetadata('lsp:' + A.pub, 'json');
check(e.value && e.value.pubkey === A.pub && e.metadata && e.metadata.c > 0, 'the file store holds lsp:<pk> with the request\'s clock in the sidecar', e.metadata);
const vfile = path.join(boxDir, 'kv', 'lsp', A.pub + '.v');
check((await fs.stat(vfile)).isFile() && (await fs.stat(vfile)).mode % 0o1000 === 0o600, 'the value is a file under kv/lsp/, mode 600', vfile);
r = await B('GET', '/lsps');
check(r.status === 200 && r.json.lsps.length === 1 && r.json.lsps[0].pubkey === A.pub && !('signature' in r.json.lsps[0]) && r.json.lsps[0].stale === false, '/lsps on the box ranks and strips as the worker does', r.json);

// the limit, per address (rlRegister 3 here)
r = await B('POST', '/lsps/register', regBody(A)); r = await B('POST', '/lsps/register', regBody(A));
check(r.status === 200, 'the 3rd registration from one address is served', r.json);
r = await B('POST', '/lsps/register', regBody(A));
check(r.status === 429 && /too many/.test(r.json.error), 'the 4th is 429 — the box has the worker\'s rule', r.json);
r = await B('POST', '/lsps/register', regBody(A), { 'cf-connecting-ip': '8.8.8.8' });
check(r.status === 429, 'a cf-connecting-ip a client sends itself is dropped (still the same bucket)', r.json);
r = await B('POST', '/lsps/register', regBody(A), { 'x-forwarded-for': '203.0.113.9' });
check(r.status === 200, 'the last hop of X-Forwarded-For (Caddy\'s, on loopback) is the address — its own bucket', r.json);
check(clientAddress({ socket: { remoteAddress: '::ffff:127.0.0.1' }, headers: { 'x-forwarded-for': '1.2.3.4, 203.0.113.9' } }) === '203.0.113.9' && clientAddress({ socket: { remoteAddress: '10.9.0.1' }, headers: { 'x-forwarded-for': '1.2.3.4' } }) === '10.9.0.1', 'clientAddress: the last hop when the peer is loopback; the peer itself otherwise', null);

// the body cap (100 KB here), with and without a Content-Length
r = await B('POST', '/backup', Buffer.alloc(200 * 1024, 32));
check(r.status === 413 && /cap/.test(r.json.error), 'a 200 KB body with a Content-Length is 413', r.json);
{
  const big = Buffer.alloc(200 * 1024, 32);
  const stream = new ReadableStream({ start(c) { c.enqueue(big.subarray(0, 100000)); c.enqueue(big.subarray(100000)); c.close(); } });
  let st = 0; try { const rr = await realFetch(BURL + '/backup', { method: 'POST', body: stream, duplex: 'half', headers: { 'content-type': 'application/json' } }); st = rr.status; await rr.text(); } catch (e2) { st = 'err ' + e2.message; }
  check(st === 413, 'a chunked body (no Content-Length) is cut at the cap too: 413', st);
}

// names and the lnurlp lookup with its 60-s memory
r = await B('POST', '/names/claim', nameOp(A, 'claim', 'alice'));
check(r.status === 200 && r.json.ok === true, 'A claims alice on the box', r.json);
r = await B('GET', '/.well-known/lnurlp/alice');
check(r.status === 200 && r.json.status === 'OK' && r.json.hits === 1 && r.headers.get('cache-control') === 'public, max-age=60', 'the lnurlp lookup asks the provider and answers its JSON', r.json);
r = await B('GET', '/.well-known/lnurlp/alice');
check(r.status === 200 && r.json.hits === 1 && stubHits === 1, 'the second lookup inside 60 s is answered from the box\'s memory (the provider asked once)', { hits: stubHits });
r = await B('GET', '/.well-known/lnurlp/nobody');
check(r.status === 404 && r.json.reason === 'unknown name', 'an unknown name is 404', r.json);

// the copy: challenge → push → meta → fetch → forget
const chal = async (base) => (await call(base, 'GET', '/backup/challenge?pubkey=' + wpub)).json.nonce;
r = await B('POST', '/backup', Object.assign(signedWith('backup-push', await chal(BURL)), { blob: copy(1) }));
check(r.status === 200 && r.json.ok === true && r.json.version === 1 && /^[0-9a-f]{64}$/.test(r.json.fingerprint), 'a copy v1 lands on the box with its fingerprint', r.json);
r = await B('POST', '/backup/meta', signedWith('backup-read', await chal(BURL)));
check(r.status === 200 && r.json.found === true && r.json.version === 1, '/backup/meta answers the number', r.json);
r = await B('POST', '/backup/fetch', signedWith('backup-read', await chal(BURL)));
check(r.status === 200 && r.json.found === true && r.json.blob.version === 1 && JSON.stringify(r.json.blob.encrypted_data) === '[1,1,1]', '/backup/fetch hands the copy back', r.json);
r = await B('POST', '/backup/forget', signedWith('backup-forget', await chal(BURL)));
check(r.status === 200 && r.json.existed === true, 'forget', r.json);
e = await reg.store.getWithMetadata('tomb:backup:' + wpub);
check(e.value === '1' && e.metadata && e.metadata.c > 0 && (await reg.store.get('backup:' + wpub)) === null, 'the forget leaves tomb:backup:<pk> in the file store', e);

// the SCB: PUT then GET, bytes equal
const scb = randomBytes(1024); const sts = nowS();
const scbHash = createHash('sha256').update(scb).digest('hex');
r = await B('PUT', '/lsp-backup', scb, { 'content-type': 'application/octet-stream', 'x-lij-pubkey': A.pub, 'x-lij-ts': String(sts), 'x-lij-sig': lndSign(A.priv, canonicalScbPush(A.pub, sts, scbHash)) });
check(r.status === 200 && r.json.sha256 === scbHash && r.json.size === 1024, 'an SCB lands (1 KB, node-key signed)', r.json);
{
  const rr = await realFetch(BURL + '/lsp-backup', { headers: { 'x-lij-pubkey': A.pub, 'x-lij-ts': String(sts), 'x-lij-sig': lndSign(A.priv, canonicalScbGet(A.pub, sts)) } });
  const got = Buffer.from(await rr.arrayBuffer());
  check(rr.status === 200 && got.equals(scb) && rr.headers.get('x-lij-sha256') === scbHash, 'the SCB comes back byte for byte', rr.status);
}
r = await B('POST', '/lsps1/channel', { any: 1 });
check(r.status === 410, '/lsps1/channel is 410 on the box too', r.json);
r = await B('GET', '/mirror/keys');
check(r.status === 503, 'the box\'s own /mirror/* answer 503 (it drives the mirror; nobody drives it)', r.json);

// ── the two doors converge ──
let n = await reg.reconciler.cycle();
check(n.pushed >= 1 && n.pulled === 0 && n.deleted_there >= 1, 'the first cycle pushes the box\'s records and its tombstones to the worker', n);
check(JSON.stringify(wkv.store.get('lsp:' + A.pub) && JSON.parse(new TextDecoder().decode(wkv.store.get('lsp:' + A.pub).v))) === JSON.stringify(await reg.store.get('lsp:' + A.pub, 'json')) && wkv.store.get('lsp:' + A.pub).meta.c === (await reg.store.getWithMetadata('lsp:' + A.pub)).metadata.c, 'the worker holds lsp:<pk> — the same bytes, the same clock', null);
check(wkv.store.has('name:alice') && wkv.store.has('lspscb:' + A.pub) && wkv.store.has('lspscbmeta:' + A.pub) && wkv.store.has('tomb:backup:' + wpub) && !wkv.store.has('backup:' + wpub) && ![...wkv.store.keys()].some((k) => k.startsWith('bkpchal:')), 'the name, the SCB and its meta, the copy\'s tombstone crossed; no challenge did', [...wkv.store.keys()]);
n = await reg.reconciler.cycle();
check(n.pushed === 0 && n.pulled === 0 && n.deleted_here === 0 && n.deleted_there === 0, 'a second cycle moves nothing (level)', n);
r = await Wc('GET', '/lsps');
check(r.status === 200 && r.json.lsps.length === 1 && r.json.lsps[0].pubkey === A.pub, 'the worker door now lists the provider', r.json);
// a write at the worker door → the box
r = await Wc('POST', '/names/claim', nameOp(A, 'claim', 'bob'));
check(r.status === 200, 'A claims bob at the worker door', r.json);
r = await Wc('POST', '/backup', Object.assign(signedWith('backup-push', await chal(WURL)), { blob: copy(5) }));
check(r.status === 200 && r.json.version === 5, 'a copy v5 lands at the worker door (newer than the forget)', r.json);
n = await reg.reconciler.cycle();
check(n.pulled === 2 && (await reg.store.get('name:bob', 'json')).lsp_pubkey === A.pub && (await reg.store.get('backup:' + wpub, 'json')).version === 5, 'the cycle pulls bob and the copy v5 to the box', n);
check((await reg.store.getWithMetadata('name:bob')).metadata.c === wkv.store.get('name:bob').meta.c, 'a pulled key keeps the writer\'s clock', null);
// a release at the worker → gone on the box, with a tombstone
r = await Wc('POST', '/names/release', nameOp(A, 'release', 'bob'));
check(r.status === 200 && r.json.released === true, 'bob released at the worker', r.json);
n = await reg.reconciler.cycle();
check(n.deleted_here === 1 && (await reg.store.get('name:bob')) === null && (await reg.store.get('tomb:name:bob')) === '1', 'the box deletes bob and keeps the tombstone', n);
// a newer copy at the box → the worker; a forget at the box → the worker
r = await B('POST', '/backup', Object.assign(signedWith('backup-push', await chal(BURL)), { blob: copy(6) }));
check(r.status === 200 && r.json.version === 6, 'a copy v6 lands on the box (v5 was there from the worker)', r.json);
n = await reg.reconciler.cycle();
check(n.pushed === 1 && JSON.parse(new TextDecoder().decode(wkv.store.get('backup:' + wpub).v)).version === 6, 'the worker now holds v6', n);
r = await B('POST', '/backup/forget', signedWith('backup-forget', await chal(BURL)));
n = await reg.reconciler.cycle();
check(r.status === 200 && n.deleted_there === 1 && !wkv.store.has('backup:' + wpub) && wkv.store.has('tomb:backup:' + wpub), 'a forget on the box deletes at the worker', n);
// a copy older than the tombstone pushed at the worker is refused there (the tombstone is newer): the engine's own
// push of a NEW copy after a forget is newer and lands on both
r = await Wc('POST', '/backup', Object.assign(signedWith('backup-push', await chal(WURL)), { blob: copy(1) }));
check(r.status === 200, 'after a forget the wallet starts again at v1 — the worker accepts it (no stored copy)', r.json);
n = await reg.reconciler.cycle();
check(n.pulled === 1 && (await reg.store.get('backup:' + wpub, 'json')).version === 1, 'and the box pulls it (the value is newer than the tombstone)', n);
// an unregister: the record goes, the 20-min lspgone travels with its expiry
const uts = nowS() + 2;
r = await B('POST', '/lsps/unregister', { pubkey: A.pub, ts: uts, signature: lndSign(A.priv, canonicalUnregisterMsg(A.pub, uts)) }, { 'x-forwarded-for': '198.51.100.7' });   // its own address: the registration bucket (3/min here) is spent
check(r.status === 200 && r.json.removed === true, 'A unregisters on the box', r.json);
n = await reg.reconciler.cycle();
const gone = wkv.store.get('lspgone:' + A.pub);
check(n.deleted_there === 1 && n.pushed === 1 && !wkv.store.has('lsp:' + A.pub) && wkv.store.has('tomb:lsp:' + A.pub) && gone && Math.abs(gone.exp - (nowS() + 1200)) <= 3, 'the worker loses the record, keeps the tombstone, and the lspgone arrives with its expiry', n);
// a big copy crosses whole (the real cap is 8 MB; 400 KB here, under the test server's 100 KB cap? no — pushed by the mirror, not a client)
{
  const bytes = Array.from(randomBytes(300 * 1024));
  r = await Wc('POST', '/backup', Object.assign(signedWith('backup-push', await chal(WURL)), { blob: copy(2, bytes) }));
  check(r.status === 200 && r.json.version === 2, 'a 300 KB copy v2 lands at the worker door', r.json);
  n = await reg.reconciler.cycle();
  const got = await reg.store.get('backup:' + wpub, 'json');
  check(n.pulled === 1 && got && got.version === 2 && got.encrypted_data.length === bytes.length && got.encrypted_data[1000] === bytes[1000], 'the mirror pulls it whole (the mirror is not under the client body cap)', n);
}

// ── the export: an empty second box against the same worker ──
const reg2 = await startRegistry({ dir: box2Dir, port: 0, host: 'registry2.test', mirrorUrl: WURL, mirrorFirstDelayMs: 1e9, log: () => {} });
n = await reg2.reconciler.cycle();
// what the worker holds, by effect: a value (newer than any tombstone of its key) or a tombstone (newer than any value)
const wAll = [...wkv.store.keys()].filter((k) => !k.startsWith('bkpchal:'));
const wVals = wAll.filter((k) => !k.startsWith('tomb:') && !(wkv.store.has('tomb:' + k) && wkv.store.get('tomb:' + k).meta.c > wkv.store.get(k).meta.c)).sort();
const wTombs = wAll.filter((k) => k.startsWith('tomb:') && !(wkv.store.has(k.slice(5)) && wkv.store.get(k.slice(5)).meta.c >= wkv.store.get(k).meta.c)).sort();
const b2keys = (await reg2.store.entries()).map((x) => x.name).sort();
check(n.pulled === wVals.length && wVals.every((k) => b2keys.includes(k)) && wTombs.every((k) => b2keys.includes(k)) && b2keys.length === wVals.length + wTombs.length, 'an empty box pulls every record the worker holds (' + wVals.length + ' values, ' + wTombs.length + ' tombstones) — the export', { n, wVals, wTombs, b2keys });
let same = true;
for (const k of wVals) { const a = Buffer.from(wkv.store.get(k).v), b = Buffer.from(await reg2.store.get(k, 'arrayBuffer')); if (!a.equals(b)) same = false; }
check(same && wVals.length >= 4, 'every value byte for byte', null);
n = await reg2.reconciler.cycle();
check(n.pulled + n.pushed + n.deleted_here + n.deleted_there === 0, 'the second box is level after one cycle', n);
r = await call('http://127.0.0.1:' + reg2.port, 'GET', '/lsps');
check(r.status === 200 && Array.isArray(r.json.lsps) && r.json.lsps.length === 0, 'the second box answers /lsps from its own files (A left; empty)', r.json);

// ── the file store itself ──
const fsStore = await new FileStore(path.join(root, 'fs')).init();
await fsStore.put('x:1', 'one', { metadata: { c: 5 } }); await fsStore.put('x:2', new Uint8Array([1, 2, 3])); await fsStore.put('y:odd/name %', 'v');
await fsStore.put('x:3', 'soon', { expirationTtl: 1 });
let l = await fsStore.list({ prefix: 'x:', limit: 2 });
check(l.keys.length === 2 && l.list_complete === false && l.cursor === 'x:2' && l.keys[0].metadata.c === 5, 'list: prefix, limit and a cursor', l);
l = await fsStore.list({ prefix: 'x:', limit: 2, cursor: l.cursor });
check(l.keys.length === 1 && l.keys[0].name === 'x:3' && l.list_complete === true && l.keys[0].expiration > nowS() - 1, 'list: the page after the cursor', l);
check((await fsStore.get('y:odd/name %')) === 'v' && (await fsStore.entries()).some((x) => x.name === 'y:odd/name %'), 'a key with odd characters round-trips through the percent-encoded file name', await fsStore.entries());
check(Buffer.from(await fsStore.get('x:2', 'arrayBuffer')).equals(Buffer.from([1, 2, 3])) && (await fsStore.get('x:2', { type: 'arrayBuffer', cacheTtl: 30 })) instanceof ArrayBuffer, 'bytes come back as an ArrayBuffer (type as a word or in the options)', null);
const m = await fsStore.get(['x:1', 'x:9']);
check(m.get('x:1') === 'one' && m.get('x:9') === null, 'a bulk get answers a Map with null for the absent', [...m]);
await sleep(1200);
check((await fsStore.get('x:3')) === null && !(await fsStore.entries()).some((x) => x.name === 'x:3'), 'an expired entry reads as absent and is swept from the listing', null);
let threw = false; try { await fsStore.put('a'.repeat(300), 'x'); } catch (_) { threw = true; }
check(threw, 'a key too long for a file name is refused', null);
const tombExp = (await reg.store.entries()).find((x) => x.name === 'tomb:name:bob');
check(tombExp && Math.abs(tombExp.expiration - (nowS() + TOMB_TTL_S)) <= 5, 'a tombstone in the file store expires in 7 days', tombExp);

await reg.close(); await reg2.close();
await new Promise((r2) => W.close(r2)); await new Promise((r2) => stub.close(r2));
await fs.rm(root, { recursive: true, force: true });
console.log(fails ? 'FAIL · test-node · ' + fails + ' failed' : 'PASS · test-node (the port over HTTP; the two doors converge; the export; the file store)');
process.exit(fails ? 1 : 0);
