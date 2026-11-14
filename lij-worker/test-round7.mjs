// 0.19.0 (S66 Wed 2026-11-04, box recovery v0.1 — DP's rulings 16:19) — THE STATE KIT'S DOOR, /lsp-state: the SCB door's
// twin. The box's own state in one age-encrypted archive a day (ciphertext here by construction); node-key signed over
// lijox-statepush:v1:<pubkey>:<ts>:<sha256>; its OWN KV keys (lspstate:*), never the SCB's; latest + one previous
// generation; the same copy again is an OK, never a rotation; an older push is refused; 20 MB the line; the GET signed
// over lijox-stateget:v1:<pubkey>:<ts>, ?gen=prev for the previous generation.
// Run: node test-round7.mjs   (CI runs it before deploy; a red here blocks)
import * as secp from '@noble/secp256k1';
import { createHmac, createHash } from 'node:crypto';
import worker from './src/index.js';
import { canonicalScbPush, canonicalStatePush, canonicalStateGet, STATE_KIT_MAX_BYTES } from './src/index.js';

secp.etc.hmacSha256Sync = (key, ...msgs) => { const h = createHmac('sha256', Buffer.from(key)); for (const m of msgs) h.update(Buffer.from(m)); return new Uint8Array(h.digest()); };
let fails = 0;
const ok = (m) => console.log('  ok · ' + m);
const check = (c, m, extra) => { if (!c) { fails++; console.log('FAIL · ' + m + (extra !== undefined ? ' — ' + JSON.stringify(extra).slice(0, 300) : '')); } else ok(m); };
const hex = (b) => Buffer.from(b).toString('hex');
const store = new Map();
const kv = {
  get: async (k, type) => { if (!store.has(k)) return null; const v = store.get(k); if (type === 'json') { try { return JSON.parse(v); } catch (e) { return null; } } return v; },
  put: async (k, v) => { store.set(k, v); },
  delete: async (k) => { store.delete(k); },
  list: async (o) => ({ keys: [...store.keys()].filter((k) => k.startsWith(o.prefix || '')).sort().map((name) => ({ name })), list_complete: true }),
};
const env = { LIJ_KV: kv };
const call = async (method, path, body, headers) => {
  const init = { method, headers: Object.assign({ 'Content-Type': 'application/octet-stream' }, headers || {}) };
  if (body !== undefined) init.body = body;
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
const sha = (b) => createHash('sha256').update(b).digest('hex');

const lp = keypair(), other = keypair();
const put = async (bytes, ts, over) => call('PUT', '/lsp-state', bytes, Object.assign({ 'x-lij-pubkey': lp.pub, 'x-lij-ts': String(ts), 'x-lij-sig': lndSign(lp.priv, canonicalStatePush(lp.pub, ts, sha(bytes))) }, over || {}));
const get = async (ts, q, kp) => { kp = kp || lp; return call('GET', '/lsp-state' + (q || ''), undefined, { 'x-lij-pubkey': kp.pub, 'x-lij-ts': String(ts), 'x-lij-sig': lndSign(kp.priv, canonicalStateGet(kp.pub, ts)) }); };
const kitA = new Uint8Array(Buffer.from('age-encryption.org/v1\n-> X25519 AAAA\n--- BBBB\n' + 'a'.repeat(4000)));
const kitB = new Uint8Array(Buffer.from('age-encryption.org/v1\n-> X25519 CCCC\n--- DDDD\n' + 'b'.repeat(4000)));
let r; const t0 = nowS();

// s1 — the first kit lands under its own keys; the SCB's keys untouched
r = await put(kitA, t0);
check(r.status === 200 && r.json.ok === true && r.json.sha256 === sha(kitA) && r.json.size === kitA.length && !r.json.repeat, 's1 the first state kit lands; the answer carries its sha256 and size', r.json);
check(store.has('lspstate:' + lp.pub) && store.has('lspstatemeta:' + lp.pub) && !store.has('lspscb:' + lp.pub) && !store.has('lspstate:' + lp.pub + ':prev'), 's1 stored under lspstate:/lspstatemeta: — never the SCB\'s keys; no previous generation yet');
// s2 — a newer kit rotates the first to prev
r = await put(kitB, t0 + 2);
check(r.status === 200 && !r.json.repeat && Buffer.from(store.get('lspstate:' + lp.pub + ':prev')).equals(Buffer.from(kitA)) && Buffer.from(store.get('lspstate:' + lp.pub)).equals(Buffer.from(kitB)), 's2 a newer kit rotates the first to prev');
// s3 — the same copy again: repeat:true, the previous generation untouched
r = await put(kitB, t0 + 4);
check(r.status === 200 && r.json.repeat === true && Buffer.from(store.get('lspstate:' + lp.pub + ':prev')).equals(Buffer.from(kitA)), 's3 the same copy again: repeat:true, prev untouched', r.json);
// s4 — an older push is refused
r = await put(kitA, t0 + 1);
check(r.status === 409 && /older/.test(r.json.error), 's4 a captured older push is refused (409)', r.json);
// s5 — a signature by another key, or over another blob, is refused
r = await call('PUT', '/lsp-state', kitA, { 'x-lij-pubkey': lp.pub, 'x-lij-ts': String(t0 + 6), 'x-lij-sig': lndSign(other.priv, canonicalStatePush(lp.pub, t0 + 6, sha(kitA))) });
check(r.status === 403, 's5 another key\'s signature is refused (403)', r.json);
r = await call('PUT', '/lsp-state', kitA, { 'x-lij-pubkey': lp.pub, 'x-lij-ts': String(t0 + 6), 'x-lij-sig': lndSign(lp.priv, canonicalStatePush(lp.pub, t0 + 6, sha(kitB))) });
check(r.status === 403, 's5 a signature over another blob\'s hash is refused (403)');
r = await call('PUT', '/lsp-state', kitA, { 'x-lij-pubkey': lp.pub, 'x-lij-ts': String(t0 + 6), 'x-lij-sig': lndSign(lp.priv, canonicalScbPush(lp.pub, t0 + 6, sha(kitA))) });
check(r.status === 403, 's5 an SCB-canon signature does not open the state door (403)');
// s6 — the window and the shape
r = await put(kitA, t0 - 700); check(r.status === 403 && /600s/.test(r.json.error), 's6 a timestamp outside the 600 s window is refused');
r = await call('PUT', '/lsp-state', kitA, { 'x-lij-pubkey': 'abcd', 'x-lij-ts': String(t0), 'x-lij-sig': 'x' }); check(r.status === 400, 's6 a short pubkey is refused (400)');
r = await call('PUT', '/lsp-state', new Uint8Array(0), { 'x-lij-pubkey': lp.pub, 'x-lij-ts': String(t0 + 8), 'x-lij-sig': lndSign(lp.priv, canonicalStatePush(lp.pub, t0 + 8, sha(new Uint8Array(0)))) }); check(r.status === 400 && /empty/.test(r.json.error), 's6 an empty body is refused');
// s7 — 20 MB the line: declared and real
check(STATE_KIT_MAX_BYTES === 20 * 1024 * 1024, 's7 the line is 20 MB');
r = await call('PUT', '/lsp-state', kitA, { 'x-lij-pubkey': lp.pub, 'x-lij-ts': String(t0 + 10), 'x-lij-sig': 'x', 'content-length': String(21 * 1024 * 1024) });
check(r.status === 413, 's7 a kit declaring 21 MB is refused before the read (413)');
const big = new Uint8Array(STATE_KIT_MAX_BYTES + 1); big[0] = 1;
r = await call('PUT', '/lsp-state', big, { 'x-lij-pubkey': lp.pub, 'x-lij-ts': String(t0 + 10), 'x-lij-sig': 'x' });
check(r.status === 413, 's7 a kit one byte over the line is refused after the read too (413)');
const near = new Uint8Array(STATE_KIT_MAX_BYTES); near[0] = 2;
r = await put(near, t0 + 12);
check(r.status === 200 && r.json.size === STATE_KIT_MAX_BYTES, 's7 a kit exactly at the line lands (the SCB door\'s 5 MB cap does not apply here)', r.json);
// s8 — the GET: signed, the newest; ?gen=prev the previous; another key gets nothing
r = await get(t0 + 14);
const body = r.status === 200 ? new Uint8Array(await r.res.arrayBuffer()) : null;
check(r.status === 200 && body && body.length === STATE_KIT_MAX_BYTES && body[0] === 2 && r.res.headers.get('x-lij-sha256') === sha(near), 's8 the signed GET returns the newest kit with its sha256 header');
r = await get(t0 + 14, '?gen=prev');
const prev = r.status === 200 ? new Uint8Array(await r.res.arrayBuffer()) : null;
check(r.status === 200 && prev && Buffer.from(prev).equals(Buffer.from(kitB)), 's8 ?gen=prev returns the previous generation');
r = await get(t0 + 14, '', other); check(r.status === 404, 's8 a node with no kit stored gets 404');
r = await call('GET', '/lsp-state', undefined, { 'x-lij-pubkey': lp.pub, 'x-lij-ts': String(t0 + 14), 'x-lij-sig': lndSign(other.priv, canonicalStateGet(lp.pub, t0 + 14)) }); check(r.status === 403, 's8 a GET signed by another key is refused (403)');
// s9 — the SCB door is untouched by all this
check(![...store.keys()].some((k) => k.startsWith('lspscb')), 's9 no SCB key was written by the state door');
// the version
r = await call('GET', '/health'); check(/^0\.(19|[2-9][0-9])\./.test(String(r.json.version)), 'the version on /health is 0.19.0 or later', r.json);

console.log(fails ? 'FAIL · test-round7 · ' + fails + ' failed' : 'PASS · test-round7 (the state kit\'s door — s1 s2 s3 s4 s5 s6 s7 s8 s9)');
process.exit(fails ? 1 : 0);
