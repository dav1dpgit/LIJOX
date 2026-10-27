// test-round3.mjs — lij-worker 0.15.0 (S63, DP's rulings on Kimi K3.1 Pro's round 2): the signed name TRANSFER (K1 —
// the old LSP hands the name to the new one in one put, no free interval), cacheTtl 30 on the backup reads (K2), and
// /lsps1/channel retired (K11).
// Run: node test-round3.mjs   (CI runs it before the deploy; a red here blocks)
import * as secp from '@noble/secp256k1';
import { createHmac, createHash, randomBytes } from 'node:crypto';
import worker from './src/index.js';
import { canonicalRegisterMsg } from './src/index.js';

secp.etc.hmacSha256Sync = (key, ...msgs) => { const h = createHmac('sha256', Buffer.from(key)); for (const m of msgs) h.update(Buffer.from(m)); return new Uint8Array(h.digest()); };
let fails = 0;
const ok = (m) => console.log('  ok · ' + m);
const check = (c, m, extra) => { if (!c) { fails++; console.log('FAIL · ' + m + (extra !== undefined ? ' — ' + JSON.stringify(extra).slice(0, 300) : '')); } else ok(m); };
const hex = (b) => Buffer.from(b).toString('hex');

// ── an in-memory KV that records the options each get was given ──
const store = new Map(); const getOpts = [];
const kv = {
  get: async (k, typeOrOpts) => {
    const opts = (typeOrOpts && typeof typeOrOpts === 'object') ? typeOrOpts : { type: typeOrOpts };
    getOpts.push({ k, opts });
    if (Array.isArray(k)) { const m = new Map(); for (const n of k) m.set(n, store.has(n) ? store.get(n) : null); return m; }
    if (!store.has(k)) return null;
    const v = store.get(k);
    if (opts.type === 'json') { try { return JSON.parse(v); } catch (e) { return null; } }
    return v;
  },
  put: async (k, v) => { store.set(k, v); },
  delete: async (k) => { store.delete(k); },
  list: async (o) => { const all = [...store.keys()].filter((k) => k.startsWith(o.prefix || '')).sort(); return { keys: all.map((name) => ({ name })), list_complete: true }; },
};
const env = { LIJ_KV: kv, LIJ_ADAPTER_URL: 'https://adapter.example', LIJ_ADAPTER_SECRET: 's' };
const call = async (method, path, body, headers) => {
  const init = { method, headers: Object.assign({ 'Content-Type': 'application/json' }, headers || {}) };
  if (body !== undefined) init.body = typeof body === 'string' || body instanceof Uint8Array ? body : JSON.stringify(body);
  const r = await worker.fetch(new Request('https://lij-worker.test' + path, init), env, {});
  let j = null; try { j = await r.clone().json(); } catch (e) {}
  return { status: r.status, json: j, res: r };
};
const ZB32 = 'ybndrfg8ejkmcpqxot1uwisza345h769';
function zb32enc(bytes) { let bits = 0, acc = 0, out = ''; for (const b of bytes) { acc = (acc << 8) | b; bits += 8; while (bits >= 5) { bits -= 5; out += ZB32[(acc >>> bits) & 31]; } } if (bits > 0) out += ZB32[(acc << (5 - bits)) & 31]; return out; }
const dsha256 = (buf) => { const a = createHash('sha256').update(buf).digest(); return new Uint8Array(createHash('sha256').update(a).digest()); };
function lndSign(privKey, msg) { const digest = dsha256(Buffer.concat([Buffer.from('Lightning Signed Message:'), Buffer.from(msg, 'utf8')])); const sig = secp.sign(digest, privKey); const out = new Uint8Array(65); out[0] = 27 + 4 + sig.recovery; out.set(sig.toCompactRawBytes(), 1); return zb32enc(out); }
const nowS = () => Math.floor(Date.now() / 1000);
function keypair() { const priv = secp.utils.randomPrivateKey(); return { priv, pub: hex(secp.getPublicKey(priv, true)) }; }
function regBody(kp) {
  const body = { name: 'LSP ' + kp.pub.slice(0, 6), pubkey: kp.pub, endpoint: 'https://lsp-' + kp.pub.slice(0, 6) + '.example', route_endpoint: 'https://lsp-' + kp.pub.slice(0, 6) + '.example', route_macaroon: 'tok' + kp.pub.slice(0, 8), wss_url: 'wss://lsp-' + kp.pub.slice(0, 6) + '.example/ws', fee_ppm: 250, supports_jit: true, ts: nowS() };
  body.signature = lndSign(kp.priv, canonicalRegisterMsg(body));
  return body;
}
const nameMsg = (kind, name, pk, ts, extra) => 'lijox-name:v1:' + [kind, name, pk, String(ts)].concat(extra !== undefined ? [extra] : []).map(encodeURIComponent).join(':');
const nameOp = (kp, kind, name, extra) => { const ts = nowS(); const b = { name, lsp_pubkey: kp.pub, ts }; if (extra) b.to_lsp_pubkey = extra; b.signature = lndSign(kp.priv, nameMsg(kind, name, kp.pub, ts, extra)); return b; };

// ── K1: the transfer ──
const A = keypair(), B = keypair(), C = keypair(), Z = keypair();   // A, B, C registered; Z is not
for (const kp of [A, B, C]) { const r = await call('POST', '/lsps/register', regBody(kp)); check(r.status === 200, 'registered ' + kp.pub.slice(0, 8), r.json); }
let r = await call('POST', '/names/claim', nameOp(A, 'claim', 'alice'));
check(r.status === 200 && r.json.ok === true, 'K1 A claims alice', r.json);
r = await call('POST', '/names/transfer', nameOp(B, 'transfer', 'alice', C.pub));
check(r.status === 403 && /not yours/.test(r.json.error), 'K1 B (not the owner) cannot transfer alice', r.json);
r = await call('POST', '/names/transfer', nameOp(A, 'transfer', 'alice', Z.pub));
check(r.status === 403 && /unknown LSP \(to\)/.test(r.json.error), 'K1 a transfer to an unregistered LSP is refused', r.json);
r = await call('POST', '/names/transfer', nameOp(A, 'transfer', 'alice', A.pub));
check(r.status === 400 && /is the signer/.test(r.json.error), 'K1 a transfer to oneself is refused', r.json);
const bad = nameOp(A, 'transfer', 'alice', B.pub); bad.to_lsp_pubkey = C.pub;   // signed for B, sent for C
r = await call('POST', '/names/transfer', bad);
check(r.status === 403 && /signature/.test(r.json.error), 'K1 the NEW pubkey is inside the signed message — a swapped target does not verify', r.json);
r = await call('POST', '/names/transfer', nameOp(A, 'transfer', 'alice', B.pub));
const rec = JSON.parse(store.get('name:alice'));
check(r.status === 200 && r.json.ok === true && r.json.lsp_pubkey === B.pub && r.json.from === A.pub && r.json.existed === true && rec.lsp_pubkey === B.pub && rec.transferred_from === A.pub, 'K1 A → B: alice moves in one put, the record names both', r.json);
r = await call('POST', '/names/claim', nameOp(C, 'claim', 'alice'));
check(r.status === 409 && /taken/.test(r.json.error), 'K1 there was no free interval: C\'s claim right after is "taken"', r.json);
r = await call('POST', '/names/claim', nameOp(B, 'claim', 'alice'));
check(r.status === 200 && r.json.existed === true && r.json.lsp_pubkey === B.pub, 'K1 B\'s own later claim finds itself the owner (existed:true)', r.json);
r = await call('POST', '/names/release', nameOp(A, 'release', 'alice'));
check(r.status === 403 && /not yours/.test(r.json.error), 'K1 the old owner can no longer release it', r.json);
r = await call('POST', '/names/transfer', nameOp(B, 'transfer', 'bob', C.pub));
check(r.status === 200 && r.json.existed === false && JSON.parse(store.get('name:bob')).lsp_pubkey === C.pub, 'K1 a transfer of an unheld name is a claim for the new LSP', r.json);
const stale = nameOp(A, 'transfer', 'alice', B.pub); stale.ts = nowS() - 700; stale.signature = lndSign(A.priv, nameMsg('transfer', 'alice', A.pub, stale.ts, B.pub));
r = await call('POST', '/names/transfer', stale);
check(r.status === 403 && /ts outside window/.test(r.json.error), 'K1 a stale transfer (ts − 700 s) is refused', r.json);

// ── K2: cacheTtl 30 on the backup reads ──
const wpriv = randomBytes(32), wpub = hex(secp.getPublicKey(wpriv, true));
const digest = (action, nonce, pk) => createHash('sha256').update(Buffer.concat([Buffer.from('lij-backup-v1'), Buffer.from(action), Buffer.from(nonce, 'hex'), Buffer.from(pk, 'hex')])).digest();
const signedWith = (action, nonce) => ({ pubkey_hex: wpub, nonce, signature: hex(secp.sign(digest(action, nonce, wpub), wpriv).toCompactRawBytes()) });
const chal = async () => (await call('GET', '/backup/challenge?pubkey=' + wpub)).json.nonce;
getOpts.length = 0;
r = await call('POST', '/backup', Object.assign(signedWith('backup-push', await chal()), { blob: { pubkey_hex: wpub, version: 1, saved_at_ms: Date.now(), encrypted_data: [1] } }));
check(r.status === 200 && r.json.ok === true, 'K2 a backup lands', r.json);
const reads = () => getOpts.filter((g) => g.k === 'backup:' + wpub);
check(reads().length === 1 && reads()[0].opts.cacheTtl === 30, 'K2 the push\'s own read of the stored copy asks cacheTtl 30', reads());
getOpts.length = 0; r = await call('POST', '/backup/fetch', signedWith('backup-read', await chal()));
check(r.status === 200 && reads().length === 1 && reads()[0].opts.cacheTtl === 30, 'K2 the fetch reads with cacheTtl 30', { status: r.status, reads: reads() });
getOpts.length = 0; r = await call('POST', '/backup/meta', signedWith('backup-read', await chal()));
check(r.status === 200 && reads().length === 1 && reads()[0].opts.cacheTtl === 30, 'K2 the meta read with cacheTtl 30', { status: r.status, reads: reads() });
getOpts.length = 0; r = await call('POST', '/backup/forget', signedWith('backup-forget', await chal()));
check(r.status === 200 && reads().length === 1 && reads()[0].opts.cacheTtl === 30, 'K2 the forget read with cacheTtl 30', { status: r.status, reads: reads() });

// ── K11: /lsps1/channel retired ──
let fetched = false; globalThis.fetch = async () => { fetched = true; return new Response('{}'); };
r = await call('POST', '/lsps1/channel', { any: 1 });
check(r.status === 410 && /retired/.test(r.json.error) && !fetched, 'K11 /lsps1/channel answers 410 and never calls the adapter', r.json);
r = await call('GET', '/lsps1/channel');
check(r.status === 410, 'K11 any method: 410');

// ── the version ──
r = await call('GET', '/health'); check(/^0\.(1[5-9]|[2-9][0-9])\./.test(String(r.json.version)), 'the version on /health is 0.15.0 or later', r.json);

console.log(fails ? 'FAIL · test-round3 · ' + fails + ' failed' : 'PASS · test-round3 (K1 K2 K11)');
process.exit(fails ? 1 : 0);
