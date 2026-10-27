// test-round4.mjs — lij-worker 0.16.0 (S63, Kimi K3.1 Pro round 2 K3/K8 — DP's numbers): the per-address rate limit
// through the Workers rate-limit bindings — RL_REGISTER on the registry writes, RL_WRITE on the other write routes;
// over the limit 429; the reads never limited; no binding → nothing limited (the shape rules stand on their own).
// Run: node test-round4.mjs   (CI runs it before the deploy; a red here blocks)
import worker from './src/index.js';
let fails = 0;
const ok = (m) => console.log('  ok · ' + m);
const check = (c, m, extra) => { if (!c) { fails++; console.log('FAIL · ' + m + (extra !== undefined ? ' — ' + JSON.stringify(extra).slice(0, 300) : '')); } else ok(m); };
const store = new Map();
const kv = {
  get: async (k, t) => { if (Array.isArray(k)) { const m = new Map(); for (const n of k) m.set(n, store.has(n) ? store.get(n) : null); return m; } if (!store.has(k)) return null; const v = store.get(k); const type = (t && typeof t === 'object') ? t.type : t; if (type === 'json') { try { return JSON.parse(v); } catch (e) { return null; } } return v; },
  put: async (k, v) => { store.set(k, v); }, delete: async (k) => { store.delete(k); },
  list: async (o) => ({ keys: [...store.keys()].filter((k) => k.startsWith(o.prefix || '')).map((name) => ({ name })), list_complete: true }),
};
// a fake binding: counts calls per key; refuses past the limit
const mk = (limit) => { const seen = new Map(); return { calls: seen, limit: async ({ key }) => { const n = (seen.get(key) || 0) + 1; seen.set(key, n); return { success: n <= limit }; } }; };
const RL_REGISTER = mk(2), RL_WRITE = mk(3);
const env = { LIJ_KV: kv, RL_REGISTER, RL_WRITE };
const call = async (method, path, body, ip, e = env) => {
  const init = { method, headers: { 'Content-Type': 'application/json', 'cf-connecting-ip': ip || '203.0.113.5' } };
  if (body !== undefined) init.body = JSON.stringify(body);
  const r = await worker.fetch(new Request('https://lij-worker.test' + path, init), e, {});
  let j = null; try { j = await r.clone().json(); } catch (x) {}
  return { status: r.status, json: j };
};
// RL_REGISTER on /lsps/register (a bad body: the limit is checked BEFORE the body — the first two answer 400, the third 429)
let r = await call('POST', '/lsps/register', { x: 1 }); check(r.status === 400, 'r1 the first register from an address: through to the shape rules (400 on junk)', r.json);
r = await call('POST', '/lsps/register', { x: 1 }); check(r.status === 400, 'r2 the second: through');
r = await call('POST', '/lsps/register', { x: 1 }); check(r.status === 429 && /too many requests/.test(r.json.error), 'r3 the third within the minute: 429 — the limit sits before the body is read', r.json);
r = await call('POST', '/lsps/unregister', { x: 1 }); check(r.status === 429, 'r4 /lsps/unregister shares the registry limit (the same address)');
r = await call('POST', '/lsps/register', { x: 1 }, '198.51.100.9'); check(r.status === 400, 'r5 another address: through');
check([...RL_REGISTER.calls.keys()].every((k) => k.startsWith('RL_REGISTER:')), 'r6 the key carries the binding name and the address');
// RL_WRITE on the other writes
r = await call('GET', '/backup/challenge?pubkey=' + '02' + '11'.repeat(32)); check(r.status === 200, 'w1 a challenge: through');
r = await call('POST', '/names/claim', { x: 1 }); check(r.status === 400, 'w2 a names write: through (the shape rule answers)');
r = await call('POST', '/backup/fetch', { x: 1 }); check(r.status === 400, 'w3 a backup read-with-signature: through');
r = await call('POST', '/backup', { x: 1 }); check(r.status === 429, 'w4 the fourth write from the address within the minute: 429');
r = await call('PUT', '/lsp-backup', undefined); check(r.status === 429, 'w5 an SCB push counts as a write: 429');
r = await call('GET', '/lsp-backup?x=1', undefined); check(r.status !== 429, 'w6 the SCB read is not limited (' + r.status + ')');
r = await call('GET', '/lsps'); check(r.status === 200, 'w7 the registry listing is not limited');
r = await call('GET', '/health'); check(r.status === 200 && /^0\.(1[6-9]|[2-9][0-9])\./.test(String(r.json.version)), 'w8 /health is not limited; the version is 0.16.0 or later', r.json);
// no binding → nothing limited
const bare = { LIJ_KV: kv };
for (let i = 0; i < 5; i++) r = await call('POST', '/lsps/register', { x: 1 }, '203.0.113.5', bare);
check(r.status === 400, 'n1 without the bindings (the tests\' env, an older wrangler) nothing is limited');
// a binding that throws never refuses a wallet
const broken = { LIJ_KV: kv, RL_REGISTER: { limit: async () => { throw new Error('binding down'); } } };
r = await call('POST', '/lsps/register', { x: 1 }, '203.0.113.5', broken); check(r.status === 400, 'n2 a binding that throws lets the request through');
console.log(fails ? 'FAIL · test-round4 · ' + fails + ' failed' : 'PASS · test-round4 (K3/K8 the rate limit)');
process.exit(fails ? 1 : 0);
