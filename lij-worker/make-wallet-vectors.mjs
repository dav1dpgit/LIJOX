// 0.25.0 (S72, F — docs/design/routes/sigcheck-r1.md): the table the wallet engine's own check is tested against.
//
// The wallet rebuilds a record's signed text in Rust (lij/lij-core/src/registry_check.rs). That is a third copy of
// canonicalRegisterMsg, in another language. This file keeps it in step: every record below is registered through
// this registry's own handler and read back from its own list, and the text of each is made by this registry's own
// function. The engine's test reads the table and must make the same text and accept the same signature.
//
//   node make-wallet-vectors.mjs           writes ../lij/lij-core/src/testdata/registry_vectors.json
//   node make-wallet-vectors.mjs --check   exits 1 if that file is not what this code makes now
//
// test-register-sig.mjs runs the check, so a change to the signed text cannot ship without a new table, and a new
// table fails the engine's test until its copy is changed too.
import * as secp from '@noble/secp256k1';
import { createHmac, createHash } from 'node:crypto';
import { readFileSync, writeFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import worker, { canonicalRegisterMsg, verifyLndSignedRegistration } from './src/index.js';

secp.etc.hmacSha256Sync = (key, ...msgs) => { const h = createHmac('sha256', Buffer.from(key)); for (const m of msgs) h.update(Buffer.from(m)); return new Uint8Array(h.digest()); };
const ZB32 = 'ybndrfg8ejkmcpqxot1uwisza345h769';
const zb32enc = (bytes) => { let bits = 0, acc = 0, out = ''; for (const b of bytes) { acc = (acc << 8) | b; bits += 8; while (bits >= 5) { bits -= 5; out += ZB32[(acc >>> bits) & 31]; } } if (bits > 0) out += ZB32[(acc << (5 - bits)) & 31]; return out; };
const dsha256 = (buf) => new Uint8Array(createHash('sha256').update(createHash('sha256').update(buf).digest()).digest());
// LND signmessage: dsha256('Lightning Signed Message:' + msg) → compact recoverable signature, header 27 + 4 + recId → zbase32
const lndSign = (priv, msg) => { const sig = secp.sign(dsha256(Buffer.concat([Buffer.from('Lightning Signed Message:'), Buffer.from(msg, 'utf8')])), priv); const out = new Uint8Array(65); out[0] = 27 + 4 + sig.recovery; out.set(sig.toCompactRawBytes(), 1); return zb32enc(out); };

export const FILE = fileURLToPath(new URL('../lij/lij-core/src/testdata/registry_vectors.json', import.meta.url));
export const CLOCK_MS = 1795000000000;   // a fixed clock, so the table is the same on every run

const T = {
  v: 1, sizes: [50000, 100000, 250000, 1000000], min_people: 3, max_people: 6, countdown_s: 600, wake_window_s: 180,
  max_retries: 2, strikes: 4, max_pools_per_size: 3, max_pools_total: 10, max_list_per_size: 60, max_fee_rate: 20,
  channel_pools: true, channel_sizes: [250000, 1000000], relay_url: 'wss://lsp.example.org/tatara/relay',
  relay_for_others: true, forward_payouts: false, forward_coin_checks: true, coin_check_url: 'https://filters.example.org/coin',
  ring_hash: 'ab'.repeat(32),
};
const R = [
  { reach: 'direct', endpoint: 'https://direct-lsp.example.org', wss_url: 'wss://direct-ws.example.org', filter_url: 'https://direct-filters.example.org' },
  { reach: 'cloudflare', endpoint: 'https://lsp.example.org:8443/a', wss_url: 'wss://ws.example.org:8443/a', filter_url: null },
];
const R1 = { endpoint: R[0].endpoint, route_endpoint: R[0].endpoint, wss_url: R[0].wss_url, filter_url: R[0].filter_url, filter_sp: true, routes: R };
const TW = { offered: true, quota_bytes: 5242880, keep_days_silent: 400, form: 'teos-v1' };
const base = { endpoint: 'https://lsp.example.org', fee_ppm: 250, supports_jit: true };
const full = { ...base, route_endpoint: 'https://lsp.example.org', route_macaroon: 'a1b2c3d4e5f60718293a4b5c6d7e8f90', wss_url: 'wss://lsp.example.org/ws', fee_base_sats: 1, channel_open_fee_sats: 2500, max_channel_size_sats: 5000000 };

// name → the body a provider posts (pubkey, ts and signature are added below)
const CASES = [
  ['v1, the fewest fields', { ...base, name: 'Plain' }],
  ['v1, every base field', { ...full, name: 'Plotzwerks LSP-1' }],
  ['v1, a name full of marks', { ...full, name: "Bob's Umbrel ⚡ café :;|%&+/?#=~!*() 日本" }],
  ['v1, supports_jit false and a fee that is not whole', { ...full, name: 'Half', supports_jit: false, fee_ppm: 0.5 }],
  ['v2, a filter server', { ...full, name: 'Filters', filter_url: 'https://filters.example.org', filter_sp: true }],
  ['v2, a filter server without the silent-payment index', { ...full, name: 'Filters no sp', filter_url: 'https://filters.example.org/x', filter_sp: false }],
  ['v3, the Tatara block', { ...full, name: 'Tatara', filter_url: 'https://filters.example.org', filter_sp: true, tatara: T }],
  ['v3, the Tatara block without a filter server', { ...full, name: 'Tatara alone', tatara: { ...T, channel_pools: false, channel_sizes: [], coin_check_url: '' } }],
  ['v4, two routes', { ...full, ...R1, name: 'Routes' }],
  ['v4, two routes and the Tatara block', { ...full, ...R1, name: 'Routes and Tatara', tatara: T }],
  ['v5, a tower', { ...full, ...R1, name: 'Tower', tower: TW }],
  ['v5, a tower that is not offered, no routes', { ...full, name: 'Tower off', tower: { ...TW, offered: false } }],
  ['v6, chan_confs', { ...full, ...R1, name: 'Confs', tower: TW, chan_confs: { min: 3, max: 6 } }],
  ['v6, chan_confs and nothing else', { ...base, name: 'Confs alone', chan_confs: { min: 1, max: 144 } }],
  ['v7, the rpc list', { ...full, ...R1, name: 'Inside', tatara: T, tower: TW, chan_confs: { min: 3, max: 6 }, rpc: ['lsps0'] }],
  ['v7, two words', { ...full, ...R1, name: 'Inside two', tower: TW, chan_confs: { min: 3, max: 6 }, rpc: ['lsps0', 'x2'] }],
  ['v7, the rpc list and nothing else', { ...base, name: 'Inside alone', rpc: ['lsps0'] }],
];

export async function makeVectors() {
  const realNow = Date.now;
  Date.now = () => CLOCK_MS;
  try {
    const kv = new Map();
    const env = { LIJ_KV: { get: async (k, type) => (kv.has(k) ? (type === 'json' ? JSON.parse(kv.get(k)) : kv.get(k)) : null), put: async (k, v) => { kv.set(k, v); }, delete: async (k) => { kv.delete(k); }, list: async () => ({ keys: Array.from(kv.keys()).filter((k) => k.startsWith('lsp:')).map((name) => ({ name })) }) } };
    const names = new Map();
    for (let i = 0; i < CASES.length; i++) {
      const [name, fields] = CASES[i];
      const priv = new Uint8Array(createHash('sha256').update('lijox wallet vectors ' + i).digest());
      const pubkey = Buffer.from(secp.getPublicKey(priv, true)).toString('hex');
      const body = { ...fields, pubkey, ts: Math.floor(CLOCK_MS / 1000) - i };
      body.signature = lndSign(priv, canonicalRegisterMsg(body));
      const r = await worker.fetch(new Request('https://lij-worker.test/lsps/register', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) }), env, {});
      if (r.status !== 200) throw new Error('case "' + name + '" was not taken by the registry: ' + r.status + ' ' + (await r.text()));
      names.set(pubkey, name);
    }
    const listed = (await (await worker.fetch(new Request('https://lij-worker.test/lsps'), env, {})).json()).lsps;
    if (listed.length !== CASES.length) throw new Error('the list has ' + listed.length + ' records, not ' + CASES.length);
    const cases = [];
    for (const rec of listed) {
      const text = canonicalRegisterMsg(rec);
      if (!(await verifyLndSignedRegistration(rec.pubkey, text, rec.signature))) throw new Error('a listed record does not match its own signature: ' + names.get(rec.pubkey));
      cases.push({ name: names.get(rec.pubkey), rec, text });
    }
    cases.sort((a, b) => CASES.findIndex((c) => c[0] === a.name) - CASES.findIndex((c) => c[0] === b.name));
    return JSON.stringify({ what: 'records as this registry lists them, and the text each was signed over (lij-worker/make-wallet-vectors.mjs)', clock_ms: CLOCK_MS, cases }, null, 1) + '\n';
  } finally { Date.now = realNow; }
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  const made = await makeVectors();
  if (process.argv.includes('--check')) {
    let held = ''; try { held = readFileSync(FILE, 'utf8'); } catch (e) {}
    if (held !== made) { console.log('FAIL · ' + FILE + ' is not what this code makes now — run: node make-wallet-vectors.mjs, then change the engine\'s copy (registry_check.rs) until its test passes'); process.exit(1); }
    console.log('PASS · the wallet engine\'s table is the one this code makes (' + JSON.parse(made).cases.length + ' records)');
  } else { writeFileSync(FILE, made); console.log('wrote ' + FILE + ' (' + JSON.parse(made).cases.length + ' records, ' + made.length + ' bytes)'); }
}
