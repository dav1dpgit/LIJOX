// lij-registry (Phase C, S63) — THE FILE STORE: Cloudflare KV's four verbs over plain files, for the worker's code
// running on the box (docs/design/routes/phase-c-r1.md §4.1: "one directory per key prefix, one file per key, written
// as temp + rename (atomic), no database" — no native module, THE LAW from the adapter's v0.18.5/.6 history).
//
//   <dir>/<prefix>/<rest>.v      the value's bytes (a string as UTF-8; a blob as is)
//   <dir>/<prefix>/<rest>.m      the sidecar: {"c": <clock ms | null>, "exp": <unix s | null>}
//
// The key `lsp:02ab…` lives at <dir>/lsp/02ab….v; `tomb:name:alice` at <dir>/tomb/name:alice.v (the colon is a
// legal character here; everything outside [A-Za-z0-9_:-] is percent-encoded, so no key can name a dot-file or
// another key's sidecar). Expiry (expirationTtl / expiration) is kept in the sidecar and honoured on every read and
// listing — an expired entry reads as absent and is removed — and a sweep removes the rest on a timer.
// Surface: get(key, type|opts) (also a list of keys → Map), getWithMetadata(key, type|opts) → {value, metadata},
// put(key, value, {expirationTtl|expiration, metadata}), delete(key), list({prefix, cursor, limit}) → {keys:[{name,
// metadata, expiration}], list_complete, cursor}. Values: string | Uint8Array | ArrayBuffer | Buffer.
import { promises as fs } from 'node:fs';
import path from 'node:path';
import { randomBytes } from 'node:crypto';

const SAFE_CHAR = /[A-Za-z0-9_:-]/;
function encodeRest(rest) {
  let out = '';
  for (const ch of rest) out += SAFE_CHAR.test(ch) ? ch : [...Buffer.from(ch, 'utf8')].map((b) => '%' + b.toString(16).padStart(2, '0').toUpperCase()).join('');
  return out;
}
function decodeRest(enc) {
  const bytes = [];
  for (let i = 0; i < enc.length; i++) {
    if (enc[i] === '%' && i + 2 < enc.length) { bytes.push(parseInt(enc.slice(i + 1, i + 3), 16)); i += 2; }
    else bytes.push(enc.charCodeAt(i));
  }
  return Buffer.from(bytes).toString('utf8');
}
function split(key) {
  const k = String(key);
  const i = k.indexOf(':');
  const prefix = i < 0 ? '_' : (k.slice(0, i) || '_');
  const rest = i < 0 ? k : k.slice(i + 1);
  if (!rest.length) throw new Error('bad key (empty remainder): ' + k);
  if (!/^[A-Za-z0-9_-]+$/.test(prefix)) throw new Error('bad key prefix: ' + k);
  const enc = encodeRest(rest);
  if (enc.length > 240) throw new Error('key too long: ' + k.slice(0, 40) + '…');
  return { prefix, enc };
}
const typeOf = (o) => ((o && typeof o === 'object') ? o.type : o) || 'text';
const toBytes = (v) => {
  if (typeof v === 'string') return Buffer.from(v, 'utf8');
  if (Buffer.isBuffer(v)) return v;
  if (v instanceof Uint8Array) return Buffer.from(v.buffer, v.byteOffset, v.byteLength);
  if (v instanceof ArrayBuffer) return Buffer.from(v);
  if (v && typeof v === 'object' && typeof v.getReader === 'function') throw new Error('streams are not stored');
  throw new Error('unsupported value type');
};
const asType = (buf, type) => {
  if (type === 'arrayBuffer') return buf.buffer.slice(buf.byteOffset, buf.byteOffset + buf.byteLength);
  const text = buf.toString('utf8');
  if (type === 'json') { try { return JSON.parse(text); } catch (_) { return null; } }
  return text;
};

export class FileStore {
  constructor(dir) { this.dir = path.resolve(dir); }
  async init() { await fs.mkdir(this.dir, { recursive: true }); return this; }
  paths(key) { const { prefix, enc } = split(key); const base = path.join(this.dir, prefix, enc); return { dirp: path.join(this.dir, prefix), v: base + '.v', m: base + '.m' }; }
  async readMeta(mp) {
    try { const j = JSON.parse(await fs.readFile(mp, 'utf8')); return { c: Number.isFinite(Number(j.c)) && Number(j.c) > 0 ? Number(j.c) : null, exp: Number.isFinite(Number(j.exp)) && Number(j.exp) > 0 ? Number(j.exp) : null }; }
    catch (_) { return { c: null, exp: null }; }
  }
  async removeFiles(p) { for (const f of [p.v, p.m]) { try { await fs.unlink(f); } catch (e) { if (e.code !== 'ENOENT') throw e; } } }
  // one entry: { value: Buffer, meta } or null (absent or expired — an expired one is removed)
  async entry(key) {
    const p = this.paths(key);
    let buf;
    try { buf = await fs.readFile(p.v); } catch (e) { if (e.code === 'ENOENT') return null; throw e; }
    const meta = await this.readMeta(p.m);
    if (meta.exp && meta.exp <= Date.now() / 1000) { await this.removeFiles(p); return null; }
    return { value: buf, meta };
  }
  async get(key, o) {
    if (Array.isArray(key)) { const out = new Map(); for (const k of key) out.set(k, await this.get(k, o)); return out; }
    const e = await this.entry(key);
    return e ? asType(e.value, typeOf(o)) : null;
  }
  async getWithMetadata(key, o) {
    const e = await this.entry(key);
    return { value: e ? asType(e.value, typeOf(o)) : null, metadata: e && e.meta.c ? { c: e.meta.c } : null };
  }
  async put(key, value, o) {
    const p = this.paths(key);
    const bytes = toBytes(value);
    const exp = o && o.expirationTtl ? Math.floor(Date.now() / 1000) + Number(o.expirationTtl) : (o && o.expiration ? Math.floor(Number(o.expiration)) : null);
    const c = o && o.metadata && Number.isFinite(Number(o.metadata.c)) && Number(o.metadata.c) > 0 ? Number(o.metadata.c) : null;
    await fs.mkdir(p.dirp, { recursive: true });
    const tag = '.tmp-' + randomBytes(6).toString('hex');
    await fs.writeFile(p.v + tag, bytes, { mode: 0o600 });
    await fs.rename(p.v + tag, p.v);
    await fs.writeFile(p.m + tag, JSON.stringify({ c, exp }), { mode: 0o600 });
    await fs.rename(p.m + tag, p.m);
  }
  async delete(key) { await this.removeFiles(this.paths(key)); }
  // every live key, sorted, with its clock and expiry
  async entries() {
    const out = [];
    let dirs;
    try { dirs = await fs.readdir(this.dir, { withFileTypes: true }); } catch (e) { if (e.code === 'ENOENT') return out; throw e; }
    for (const d of dirs) {
      if (!d.isDirectory() || !/^[A-Za-z0-9_-]+$/.test(d.name)) continue;
      let files;
      try { files = await fs.readdir(path.join(this.dir, d.name)); } catch (_) { continue; }
      for (const f of files) {
        if (!f.endsWith('.v') || f.includes('.tmp-')) continue;
        const enc = f.slice(0, -2);
        const name = (d.name === '_' ? '' : d.name + ':') + decodeRest(enc);
        const meta = await this.readMeta(path.join(this.dir, d.name, enc + '.m'));
        if (meta.exp && meta.exp <= Date.now() / 1000) { await this.removeFiles({ v: path.join(this.dir, d.name, f), m: path.join(this.dir, d.name, enc + '.m') }); continue; }
        out.push({ name, metadata: meta.c ? { c: meta.c } : null, expiration: meta.exp || undefined });
      }
    }
    out.sort((a, b) => (a.name < b.name ? -1 : a.name > b.name ? 1 : 0));
    return out;
  }
  async list(o) {
    const prefix = (o && o.prefix) || '';
    const limit = (o && Number.isFinite(Number(o.limit)) && Number(o.limit) > 0) ? Number(o.limit) : 1000;
    const cursor = (o && o.cursor) || null;
    let all = (await this.entries()).filter((e) => e.name.startsWith(prefix));
    if (cursor) all = all.filter((e) => e.name > cursor);
    const page = all.slice(0, limit);
    const complete = page.length === all.length;
    return { keys: page, list_complete: complete, ...(complete ? {} : { cursor: page[page.length - 1].name }) };
  }
  async sweep() { const before = await this.entries(); return before.length; }   // entries() removes the expired as it reads
  async counts() {
    const by = {};
    for (const e of await this.entries()) { const p = e.name.includes(':') ? e.name.slice(0, e.name.indexOf(':')) : '_'; by[p] = (by[p] || 0) + 1; }
    return by;
  }
}
