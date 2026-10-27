// lij-registry (Phase C, S63 — docs/design/routes/phase-c-r1.md §4.1, DP 21:41 "Go") — THE REGISTRY'S DIRECT DOOR:
// the worker's own code (../src/index.js, unchanged) run under Node on the UM890 behind Caddy, with
//   · the file store (store.js) where Cloudflare has KV,
//   · the same two limits (limiter.js: RL_REGISTER 60/min, RL_WRITE 300/min, per client address — the address Caddy
//     writes as the last hop of X-Forwarded-For, which the relay's PROXY protocol makes the client's real one; a
//     cf-connecting-ip or x-real-ip a client sends itself is dropped),
//   · the same 8 MB cap on a copy, read as the body arrives (a body with no Content-Length is cut at the cap too),
//   · a 60-s memory where the worker has Cloudflare's cache for the lnurlp lookup,
//   · the mirror (reconcile.js) to the Cloudflare door, signed with this box's own key (mirror.key, born here at the
//     first boot; its PUBKEY printed in the journal for wrangler.toml [vars] LIJ_MIRROR_PUBKEY).
// Settings (environment, /etc/lij-registry.env):
//   LIJ_REGISTRY_DIR=/srv/lij-registry   LIJ_REGISTRY_BIND=127.0.0.1   LIJ_REGISTRY_PORT=7005
//   LIJ_REGISTRY_HOST=registry.lightninginajar.xyz (the name the requests are addressed to)
//   LIJ_MIRROR_URL=https://lij-worker.dp-a95.workers.dev   LIJ_MIRROR_EVERY_MS=20000   LIJ_MIRROR_OFF=1 (no mirror)
//   LIJ_REGISTRY_RL_REGISTER=60   LIJ_REGISTRY_RL_WRITE=300   LIJ_REGISTRY_BODY_CAP=8454144 (8 MB + 64 KB)
// Run: node node/server.js   (lij-registry.service; one journal line at boot, one when the mirror moves anything)
import http from 'node:http';
import { promises as fs } from 'node:fs';
import path from 'node:path';
import { pathToFileURL } from 'node:url';
import * as secp from '@noble/secp256k1';
import worker from '../src/index.js';
import { FileStore } from './store.js';
import { memLimiter } from './limiter.js';
import { Reconciler } from './reconcile.js';

export const REGISTRY_VERSION = JSON.parse(await fs.readFile(new URL('../package.json', import.meta.url), 'utf8')).version;   // one truth: the worker's package.json
const CORS = { 'Access-Control-Allow-Origin': '*', 'Access-Control-Allow-Methods': 'GET, POST, OPTIONS', 'Access-Control-Allow-Headers': 'Content-Type, Authorization', 'Cache-Control': 'no-store' };

// the worker's lnurlp route keeps a 60-s copy of a provider's answer in Cloudflare's cache; here, in memory
export function memCache(maxEntries = 1000) {
  const m = new Map();   // url → { status, headers: [[k,v]], body: Buffer, exp }
  const ttlOf = (res) => { const cc = String(res.headers.get('cache-control') || ''); const mm = /max-age=(\d+)/.exec(cc); return mm ? Number(mm[1]) : 60; };
  return {
    match: async (req) => { const u = typeof req === 'string' ? req : req.url; const e = m.get(u); if (!e) return undefined; if (e.exp <= Date.now()) { m.delete(u); return undefined; } return new Response(e.body, { status: e.status, headers: e.headers }); },
    put: async (req, res) => { const u = typeof req === 'string' ? req : req.url; const body = Buffer.from(await res.arrayBuffer()); if (m.size >= maxEntries) m.delete(m.keys().next().value); m.set(u, { status: res.status, headers: [...res.headers], body, exp: Date.now() + ttlOf(res) * 1000 }); },
    size: () => m.size,
  };
}

const HOP = new Set(['host', 'connection', 'keep-alive', 'transfer-encoding', 'content-length', 'proxy-connection', 'te', 'trailer', 'upgrade', 'cf-connecting-ip', 'x-real-ip']);
export function clientAddress(req) {
  const peer = String(req.socket && req.socket.remoteAddress || '');
  const loop = peer === '127.0.0.1' || peer === '::1' || peer === '::ffff:127.0.0.1';
  if (loop) {
    const xff = req.headers['x-forwarded-for'];
    if (xff) { const parts = String(Array.isArray(xff) ? xff[xff.length - 1] : xff).split(',').map((s) => s.trim()).filter(Boolean); if (parts.length) return parts[parts.length - 1]; }
  }
  return peer || 'unknown';
}

// node:http → the worker's fetch(request, env, ctx) → node:http
export function nodeHandler({ fetchFn, env, host, bodyCap }) {
  const cap = Number(bodyCap) || (8 * 1024 * 1024 + 64 * 1024);
  const ctx = { waitUntil: (p) => { Promise.resolve(p).catch(() => {}); } };
  return async (req, res) => {
    try {
      const chunks = []; let total = 0; let over = false;
      if (req.method !== 'GET' && req.method !== 'HEAD' && req.method !== 'OPTIONS') {
        for await (const ch of req) { total += ch.length; if (total > cap) { over = true; break; } chunks.push(ch); }
      } else { req.resume(); }
      if (over) {
        const body = JSON.stringify({ error: 'body exceeds the ' + Math.floor(cap / 1024 / 1024) + ' MB cap' });
        res.writeHead(413, Object.assign({ 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(body), Connection: 'close' }, CORS));
        res.end(body); req.destroy(); return;
      }
      const headers = new Headers();
      for (const [k, v] of Object.entries(req.headers)) { if (HOP.has(k)) continue; try { headers.set(k, Array.isArray(v) ? v.join(', ') : String(v)); } catch (_) {} }
      headers.set('x-real-ip', clientAddress(req));
      const url = new URL(req.url || '/', 'https://' + host);
      const init = { method: req.method, headers };
      if (chunks.length) init.body = Buffer.concat(chunks);
      const r = await fetchFn(new Request(url, init), env, ctx);
      const body = Buffer.from(await r.arrayBuffer());
      const out = {};
      r.headers.forEach((v, k) => { out[k] = v; });
      out['content-length'] = String(body.length);
      res.writeHead(r.status, out);
      res.end(req.method === 'HEAD' ? undefined : body);
    } catch (e) {
      const body = JSON.stringify({ error: 'registry error: ' + String(e && e.message || e).slice(0, 200) });
      try { res.writeHead(500, Object.assign({ 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(body) }, CORS)); res.end(body); } catch (_) {}
    }
  };
}

export async function loadOrMakeKey(file) {
  try {
    const hex = (await fs.readFile(file, 'utf8')).trim();
    if (!/^[0-9a-f]{64}$/.test(hex) || !secp.utils.isValidPrivateKey(Buffer.from(hex, 'hex'))) throw new Error('mirror.key is not a 32-byte hex private key: ' + file);
    return hex;
  } catch (e) {
    if (e.code !== 'ENOENT') throw e;
    const hex = Buffer.from(secp.utils.randomPrivateKey()).toString('hex');
    await fs.mkdir(path.dirname(file), { recursive: true });
    await fs.writeFile(file + '.tmp', hex + '\n', { mode: 0o600 });
    await fs.rename(file + '.tmp', file);
    return hex;
  }
}

export async function startRegistry(opts) {
  const o = Object.assign({
    dir: process.env.LIJ_REGISTRY_DIR || '/srv/lij-registry',
    bind: process.env.LIJ_REGISTRY_BIND || '127.0.0.1',
    port: Number(process.env.LIJ_REGISTRY_PORT || 7005),
    host: process.env.LIJ_REGISTRY_HOST || 'registry.lightninginajar.xyz',
    mirrorUrl: process.env.LIJ_MIRROR_URL || 'https://lij-worker.dp-a95.workers.dev',
    mirrorEveryMs: Number(process.env.LIJ_MIRROR_EVERY_MS || 20000),
    mirrorOff: process.env.LIJ_MIRROR_OFF === '1',
    rlRegister: Number(process.env.LIJ_REGISTRY_RL_REGISTER || 60),
    rlWrite: Number(process.env.LIJ_REGISTRY_RL_WRITE || 300),
    bodyCap: Number(process.env.LIJ_REGISTRY_BODY_CAP || (8 * 1024 * 1024 + 64 * 1024)),
    log: (line) => console.log('lij-registry: ' + line),
  }, opts || {});
  const store = await new FileStore(path.join(o.dir, 'kv')).init();
  const privHex = await loadOrMakeKey(path.join(o.dir, 'mirror.key'));
  const pubHex = Buffer.from(secp.getPublicKey(Buffer.from(privHex, 'hex'), true)).toString('hex');
  if (typeof globalThis.caches === 'undefined') globalThis.caches = { default: memCache() };
  const env = { LIJ_KV: store, RL_REGISTER: memLimiter(o.rlRegister, 60), RL_WRITE: memLimiter(o.rlWrite, 60) };
  const server = http.createServer(nodeHandler({ fetchFn: worker.fetch, env, host: o.host, bodyCap: o.bodyCap }));
  server.keepAliveTimeout = 65000; server.headersTimeout = 70000; server.requestTimeout = 120000;
  await new Promise((resolve, reject) => { server.once('error', reject); server.listen(o.port, o.bind, () => { server.off('error', reject); resolve(); }); });
  const port = server.address().port;
  const sweeper = setInterval(() => { store.sweep().catch(() => {}); }, 10 * 60 * 1000); sweeper.unref();
  let reconciler = null;
  if (!o.mirrorOff && o.mirrorUrl) {
    reconciler = new Reconciler({ store, workerUrl: o.mirrorUrl, privHex, everyMs: o.mirrorEveryMs, log: o.log, fetchImpl: o.fetchImpl });
    reconciler.start(o.mirrorFirstDelayMs !== undefined ? o.mirrorFirstDelayMs : 2000);
  }
  o.log(REGISTRY_VERSION + ' listening on ' + o.bind + ':' + port + ' as ' + o.host + '; store ' + path.join(o.dir, 'kv') + ' ' + JSON.stringify(await store.counts()) + '; limits ' + o.rlRegister + '/min registrations, ' + o.rlWrite + '/min other writes, per address; copies ' + Math.floor(o.bodyCap / 1024 / 1024) + ' MB');
  o.log('mirror pubkey ' + pubHex + ' — put it in lij-worker/wrangler.toml [vars] LIJ_MIRROR_PUBKEY (the private half stays in ' + path.join(o.dir, 'mirror.key') + ')');
  o.log(reconciler ? 'mirror to ' + o.mirrorUrl + ' every ' + Math.round(o.mirrorEveryMs / 1000) + ' s (the first cycle is the export)' : 'mirror off');
  return {
    server, port, store, env, reconciler, pubHex,
    close: async () => { if (reconciler) reconciler.stop(); clearInterval(sweeper); await new Promise((r) => server.close(() => r())); },
  };
}

if (process.argv[1] && import.meta.url === pathToFileURL(path.resolve(process.argv[1])).href) {
  startRegistry().catch((e) => { console.error('lij-registry: failed to start: ' + (e && e.stack || e)); process.exit(1); });
}
