// 0.20.0 (S68 Tue 2026-11-10, Register amount sharing — docs/register-mode-plan-v2.1.md; DP's rulings of 2026-11-07):
// THE REGISTER FLAG ON THE ADDRESS LOOKUP. A shop's Register QR is its address with `?register`; the provider's answer to
// it carries a one-use rate stamp made for that one ask. So this door passes the flag on and NEVER keeps or serves that
// answer from the 60-s copy. A lookup without the flag is unchanged (asked once, served from the copy).
// Run: node test-round8.mjs   (CI runs it before deploy; a red here blocks)
import * as secp from '@noble/secp256k1';
import { createHmac, createHash } from 'node:crypto';
import worker from './src/index.js';

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


// a cache that works like Cloudflare's (keyed by URL), so a wrongly cached Register answer WOULD be served
const mem = new Map();
globalThis.caches = { default: { match: async (k) => { const h = mem.get(k.url); return h ? h.clone() : undefined; }, put: async (k, v) => { mem.set(k.url, v.clone()); } } };
const jcall = async (method, path, body) => { const r = await worker.fetch(new Request('https://lij-worker.test' + path, { method, headers: { 'Content-Type': 'application/json' }, body: body === undefined ? undefined : JSON.stringify(body) }), env, {}); let j = null; try { j = await r.clone().json(); } catch (e) {} return { status: r.status, json: j, res: r }; };
const lsp = keypair();
const canon = (await import('./src/index.js')).canonicalRegisterMsg;
const regRec = { pubkey: lsp.pub, alias: 'r8', endpoint: 'https://lsp8.example', ws_proxy_url: 'wss://ws8.example', ts: nowS() };
regRec.signature = lndSign(lsp.priv, canon ? canon(regRec) : '');
let r = await jcall('POST', '/lsps/register', regRec);
if (r.status !== 200) { store.set('lsp:' + lsp.pub, JSON.stringify({ pubkey: lsp.pub, endpoint: 'https://lsp8.example' })); ok('the provider record placed directly (the register route\'s own tests are test-register-sig.mjs)'); } else ok('the provider registered');
store.set('name:kura', JSON.stringify({ name: 'kura', lsp_pubkey: lsp.pub, ts: nowS() }));
const asked = []; let n = 0;
globalThis.fetch = async (u) => { asked.push(String(u)); n++; const reg = /[?&]register\b/.test(String(u)); return new Response(JSON.stringify(reg ? { tag: 'payRequest', callback: 'https://lsp8.example/lnurl/cb/kura/r/stamp' + n, currencies: [{ code: 'JPY', multiplier: 6666.667 }] } : { tag: 'payRequest', callback: 'https://lsp8.example/lnurl/cb/kura' }), { status: 200, headers: { 'Content-Type': 'application/json' } }); };

r = await jcall('GET', '/.well-known/lnurlp/kura');
check(r.status === 200 && r.json.callback === 'https://lsp8.example/lnurl/cb/kura' && asked[0] === 'https://lsp8.example/.well-known/lnurlp/kura' && r.res.headers.get('cache-control') === 'public, max-age=60', 'a plain lookup asks the provider without the flag and may be kept 60 s', { asked, j: r.json });
r = await jcall('GET', '/.well-known/lnurlp/kura');
check(r.status === 200 && asked.length === 1, 'the plain lookup again is served from the copy (the provider is not asked)', asked);
r = await jcall('GET', '/.well-known/lnurlp/kura?register');
check(r.status === 200 && asked.length === 2 && asked[1] === 'https://lsp8.example/.well-known/lnurlp/kura?register', 'the Register lookup is passed on WITH the flag — not answered from the plain copy', asked);
check(/\/r\/stamp2$/.test(r.json.callback) && Array.isArray(r.json.currencies) && r.res.headers.get('cache-control') === 'no-store', 'the Register answer comes through whole and says no-store', { j: r.json, cc: r.res.headers.get('cache-control') });
const first = r.json.callback;
r = await jcall('GET', '/.well-known/lnurlp/kura?register');
check(asked.length === 3 && r.json.callback !== first && /\/r\/stamp3$/.test(r.json.callback), 'a second Register lookup asks the provider again — every scan gets its own stamp', { asked: asked.length, cb: r.json.callback });
r = await jcall('GET', '/.well-known/lnurlp/kura?register=1&x=y');
check(asked.length === 4 && asked[3] === 'https://lsp8.example/.well-known/lnurlp/kura?register', 'only the bare flag is passed on, whatever else the query carries', asked[3]);
r = await jcall('GET', '/.well-known/lnurlp/kura');
check(asked.length === 4 && r.json.callback === 'https://lsp8.example/lnurl/cb/kura', 'the plain copy was never replaced by a Register answer', { asked: asked.length, cb: r.json.callback });
r = await jcall('GET', '/health'); check(/^0\.(2[0-9]|[3-9][0-9])\./.test(String(r.json.version)), 'the version on /health is 0.20.0 or later', r.json);
console.log(fails ? 'FAIL · round 8 · ' + fails : 'PASS · round 8 (the Register flag on the address lookup)');
process.exit(fails ? 1 : 0);
