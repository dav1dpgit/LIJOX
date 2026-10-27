// lij-registry (Phase C, S63) — THE MIRROR, the box's side. The registry has two doors to one set of records: this
// box (the direct door, the source of truth) and the worker on Cloudflare (the Cloudflare door; DP 21:41 "keep the
// worker as the Cloudflare door"). Each door stores what it verifies; this loop keeps the two stores level, every
// LIJ_MIRROR_EVERY_MS (20 s), by the rules in ../src/mirror.js:
//
//   1. list the worker's keys with their clocks (GET /mirror/keys, signed) and this store's;
//   2. for every key either side holds: the newer clock wins — a value or a tombstone — and is copied the other way
//      (GET /mirror/get → this store; this store → POST /mirror/put; a tombstone → POST /mirror/delete or a local
//      delete with the same tombstone). Equal clocks are the same write: nothing to do. `bkpchal:` is never looked at.
//   3. the receiving side keeps its own guards (an equal-or-newer clock, a newer tombstone, the record rules) — the
//      worker in its /mirror/put, this loop in its pull — so a stale listing (KV's list is eventually consistent)
//      can never roll a record back.
//
// The FIRST cycle on an empty store is the one-time export of phase-c-r1 §6.2: it pulls every record, name, copy and
// SCB the worker holds — no wrangler, no KV dump. A cycle moves at most MAX_OPS keys (the rest next cycle). One
// journal line when anything moved; errors once a cycle, at most one line a minute for the same error.
import * as secp from '@noble/secp256k1';
import { createHmac, createHash } from 'node:crypto';
import { mirrorable, clockOf, recordAllows, mirrorMsg, sha256Hex, TOMB_PREFIX, TOMB_TTL_S } from '../src/mirror.js';

secp.etc.hmacSha256Sync = (key, ...msgs) => { const h = createHmac('sha256', Buffer.from(key)); for (const m of msgs) h.update(Buffer.from(m)); return new Uint8Array(h.digest()); };

const MAX_OPS = 300;
const isTomb = (name) => name.startsWith(TOMB_PREFIX);

export class Reconciler {
  // store: the raw file store; workerUrl: the Cloudflare door; privHex: this box's mirror key; log: (line) => void
  constructor({ store, workerUrl, privHex, everyMs, log, fetchImpl }) {
    this.store = store;
    this.workerUrl = String(workerUrl || '').replace(/\/+$/, '');
    this.priv = Buffer.from(privHex, 'hex');
    this.pubHex = Buffer.from(secp.getPublicKey(this.priv, true)).toString('hex');
    this.everyMs = Math.max(5000, Number(everyMs) || 20000);
    this.log = log || (() => {});
    this.fetch = fetchImpl || globalThis.fetch;
    this.inFlight = false;
    this.cycles = 0;
    this.lastErr = { text: '', at: 0 };
    this.timer = null;
  }
  async signed(method, pathAndQuery, body) {
    const bytes = body === undefined ? new Uint8Array(0) : (body instanceof Uint8Array ? body : Buffer.from(body));
    const ts = Math.floor(Date.now() / 1000);
    const digest = createHash('sha256').update(mirrorMsg(method, pathAndQuery, ts, await sha256Hex(bytes))).digest();
    const sig = Buffer.from(secp.sign(digest, this.priv).toCompactRawBytes()).toString('hex');
    const init = { method, headers: { 'x-lij-mirror-ts': String(ts), 'x-lij-mirror-sig': sig, 'content-type': 'application/octet-stream' }, redirect: 'error' };
    if (method === 'POST') init.body = bytes;
    const r = await this.fetch(this.workerUrl + pathAndQuery, init);
    return r;
  }
  async listRemote() {
    const out = new Map();
    let cursor = null;
    for (let page = 0; page < 100; page++) {
      const r = await this.signed('GET', '/mirror/keys' + (cursor ? '?cursor=' + encodeURIComponent(cursor) : ''));
      if (r.status !== 200) throw new Error('/mirror/keys ' + r.status + ' ' + (await r.text()).slice(0, 200));
      const j = await r.json();
      for (const k of (j.keys || [])) if (mirrorable(k.name)) out.set(k.name, { c: Number(k.c) || 0, exp: Number.isFinite(Number(k.exp)) && Number(k.exp) > 0 ? Number(k.exp) : null });
      cursor = j.cursor || null;
      if (!cursor) break;
    }
    return out;
  }
  async listLocal() {
    const out = new Map();
    for (const e of await this.store.entries()) if (mirrorable(e.name)) out.set(e.name, { c: clockOf(e.metadata), exp: e.expiration || null });
    return out;
  }
  // the state of one key on one side: null (nothing), or { kind: 'v'|'t', c, exp }
  static state(map, name) {
    const v = map.get(name), t = map.get(TOMB_PREFIX + name);
    if (v && (!t || v.c >= t.c)) return { kind: 'v', c: v.c, exp: v.exp };
    if (t) return { kind: 't', c: t.c, exp: t.exp };
    return null;
  }
  async pull(name, remote) {
    const r = await this.signed('GET', '/mirror/get?key=' + encodeURIComponent(name));
    if (r.status === 404) return false;
    if (r.status !== 200) throw new Error('/mirror/get ' + r.status);
    const bytes = Buffer.from(await r.arrayBuffer());
    const clock = Number(r.headers.get('x-lij-clock')) || remote.c;
    const cur = await this.store.getWithMetadata(name, 'arrayBuffer');
    if (cur.value !== null && clockOf(cur.metadata) >= clock) return false;
    if (!recordAllows(name, bytes, cur.value !== null ? new Uint8Array(cur.value) : null)) return false;
    await this.store.put(name, bytes, Object.assign({ metadata: { c: clock } }, remote.exp ? { expiration: remote.exp } : {}));
    return true;
  }
  async push(name, local) {
    const cur = await this.store.getWithMetadata(name, 'arrayBuffer');
    if (cur.value === null) return false;
    const q = '/mirror/put?key=' + encodeURIComponent(name) + '&clock=' + local.c + (local.exp ? '&expiration=' + local.exp : '');
    const r = await this.signed('POST', q, new Uint8Array(cur.value));
    if (r.status !== 200) throw new Error('/mirror/put ' + r.status + ' ' + (await r.text()).slice(0, 200));
    const j = await r.json();
    return j.applied === true;
  }
  async deleteRemote(name, clock) {
    const r = await this.signed('POST', '/mirror/delete?key=' + encodeURIComponent(name) + '&clock=' + clock);
    if (r.status !== 200) throw new Error('/mirror/delete ' + r.status + ' ' + (await r.text()).slice(0, 200));
    const j = await r.json();
    return j.applied === true;
  }
  async deleteLocal(name, clock) {
    const cur = await this.store.getWithMetadata(name);
    if (cur.value !== null && clockOf(cur.metadata) >= clock) return false;
    const tomb = await this.store.getWithMetadata(TOMB_PREFIX + name);
    if (tomb.value !== null && clockOf(tomb.metadata) >= clock) return false;
    await this.store.delete(name);
    await this.store.put(TOMB_PREFIX + name, '1', { expirationTtl: TOMB_TTL_S, metadata: { c: clock } });
    return true;
  }
  async cycle() {
    const remote = await this.listRemote();
    const local = await this.listLocal();
    const names = new Set();
    for (const n of remote.keys()) names.add(isTomb(n) ? n.slice(TOMB_PREFIX.length) : n);
    for (const n of local.keys()) names.add(isTomb(n) ? n.slice(TOMB_PREFIX.length) : n);
    const n = { pulled: 0, pushed: 0, deleted_here: 0, deleted_there: 0, left: 0 };
    let ops = 0;
    for (const name of [...names].sort()) {
      if (!mirrorable(name) || isTomb(name)) continue;
      const rs = Reconciler.state(remote, name), ls = Reconciler.state(local, name);
      if (!rs && !ls) continue;
      if (rs && ls && rs.kind === ls.kind && rs.c === ls.c) continue;
      if (ops >= MAX_OPS) { n.left++; continue; }
      ops++;
      const remoteWins = !ls || (rs && (rs.c > ls.c || (rs.c === ls.c && rs.kind === 'v' && ls.kind === 't')));
      if (remoteWins) {
        if (rs.kind === 'v') { if (await this.pull(name, rs)) n.pulled++; }
        else if (await this.deleteLocal(name, rs.c)) n.deleted_here++;
      } else {
        if (ls.kind === 'v') { if (await this.push(name, ls)) n.pushed++; }
        else if (await this.deleteRemote(name, ls.c)) n.deleted_there++;
      }
    }
    this.cycles++;
    return n;
  }
  async tick() {
    if (this.inFlight) return;
    this.inFlight = true;
    try {
      const n = await this.cycle();
      const moved = n.pulled + n.pushed + n.deleted_here + n.deleted_there;
      if (moved || n.left) this.log('mirror: pulled ' + n.pulled + ', pushed ' + n.pushed + ', deleted here ' + n.deleted_here + ', there ' + n.deleted_there + (n.left ? ', ' + n.left + ' more next cycle' : '') + (this.cycles === 1 ? ' (the first cycle: the export)' : ''));
      if (this.cycles === 1) this.log('mirror: first cycle done — the store holds ' + JSON.stringify(await this.store.counts()));
    } catch (e) {
      const text = String(e && e.message || e).slice(0, 200);
      if (text !== this.lastErr.text || Date.now() - this.lastErr.at > 60000) { this.log('mirror: ' + text + ' (the worker ' + this.workerUrl + '; retrying every ' + Math.round(this.everyMs / 1000) + ' s)'); this.lastErr = { text, at: Date.now() }; }
    } finally { this.inFlight = false; }
  }
  start(firstDelayMs) {
    this.stop();
    setTimeout(() => this.tick(), Math.max(0, Number(firstDelayMs) || 0)).unref();
    this.timer = setInterval(() => this.tick(), this.everyMs);
    this.timer.unref();
  }
  stop() { if (this.timer) { clearInterval(this.timer); this.timer = null; } }
}
