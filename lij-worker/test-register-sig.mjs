// S41 register-signature fix — sign↔verify gate. Run: node test-register-sig.mjs
//
// Simulates the ADAPTER/LND side byte-for-byte (LND signmessage: compact
// recoverable ECDSA over dsha256('Lightning Signed Message:' + msg), header
// byte 27+4+recId, zbase32) and verifies with the WORKER'S ACTUAL functions
// imported from src/index.js — so a canonical-string or format mismatch
// cannot reach deploy. CI runs this before wrangler; a red here blocks.
import * as secp from '@noble/secp256k1';
import { createHmac, createHash, randomBytes } from 'node:crypto';
import worker from './src/index.js';
import { canonicalRegisterMsg, canonicalUnregisterMsg, verifyLndSignedRegistration, zbase32Decode, canonicalScbPush, canonicalScbGet, cleanFilterUrl, cleanTatara, cleanRoutes, TATARA_FIELDS, ROUTE_REACH } from './src/index.js';

// noble v2 needs an hmac for RFC6979 signing (verify/recovery does not).
secp.etc.hmacSha256Sync = (key, ...msgs) => {
  const h = createHmac('sha256', Buffer.from(key));
  for (const m of msgs) h.update(Buffer.from(m));
  return new Uint8Array(h.digest());
};

const ZB32 = 'ybndrfg8ejkmcpqxot1uwisza345h769';
function zb32enc(bytes) {
  let bits = 0, acc = 0, out = '';
  for (const b of bytes) {
    acc = (acc << 8) | b; bits += 8;
    while (bits >= 5) { bits -= 5; out += ZB32[(acc >>> bits) & 31]; }
  }
  if (bits > 0) out += ZB32[(acc << (5 - bits)) & 31];
  return out;
}
const dsha256 = (buf) => {
  const a = createHash('sha256').update(buf).digest();
  return new Uint8Array(createHash('sha256').update(a).digest());
};

// LND signmessage, exactly: dsha256 prefix+msg → SignCompact → zbase32.
function lndSign(privKey, msg) {
  const digest = dsha256(Buffer.concat([
    Buffer.from('Lightning Signed Message:'), Buffer.from(msg, 'utf8'),
  ]));
  const sig = secp.sign(digest, privKey);
  const out = new Uint8Array(65);
  out[0] = 27 + 4 + sig.recovery;           // compressed-key header (btcec)
  out.set(sig.toCompactRawBytes(), 1);
  return zb32enc(out);
}

let pass = 0, fail = 0;
const t = (name, cond) => {
  if (cond) { pass++; console.log('PASS', name); }
  else { fail++; console.log('FAIL', name); }
};

const priv = secp.utils.randomPrivateKey();
const pub = Buffer.from(secp.getPublicKey(priv, true)).toString('hex');

// LSP-1-shaped registration: URLs full of ':' and '/', a name with a space,
// fields the adapter omits (worker coerces them to 0/null).
const body = {
  name: 'Plotzwerks LSP-1',
  pubkey: pub,
  endpoint: 'https://lijox-adapter-live.example.workers.dev',
  route_endpoint: 'https://lijox-adapter-live.example.workers.dev',
  route_macaroon: 'a1b2c3d4e5f60718293a4b5c6d7e8f90',
  wss_url: 'wss://lijox-adapter-live.example.workers.dev/ws',
  fee_ppm: 250,
  supports_jit: true,
  ts: Math.floor(Date.now() / 1000),
};

// ADAPTER side: canonical from the raw POST body (same function text ships in
// lij-adapter.js — verbatim-copy is asserted by the build receipt, and any
// drift in MEANING fails the equality test below).
const adapterMsg = canonicalRegisterMsg(body);
const signature = lndSign(priv, adapterMsg);

// WORKER side: canonical from the coerced/stored record.
const stored = {
  name: body.name, pubkey: body.pubkey, endpoint: body.endpoint,
  fee_ppm: Number(body.fee_ppm),
  fee_base_sats: 0, channel_open_fee_sats: 0, max_channel_size_sats: 0,
  supports_jit: Boolean(body.supports_jit),
  route_endpoint: body.route_endpoint || null,
  route_macaroon: body.route_macaroon || null,
  wss_url: body.wss_url || null,
  uptime: 100, registered_at: Date.now(),
  ts: Number(body.ts),
};
const workerMsg = canonicalRegisterMsg(stored);

t('adapter and worker canonicals are byte-identical', workerMsg === adapterMsg);
t('valid LND-format signature verifies', await verifyLndSignedRegistration(pub, workerMsg, signature));

{ // unicode + colons inside fields survive the encoding
  const b2 = { ...body, name: '嵐 LSP:試験' };
  const m2 = canonicalRegisterMsg(b2);
  t('unicode/colon field signs and verifies', await verifyLndSignedRegistration(pub, m2, lndSign(priv, m2)));
}

// Every signed field, tampered after signing → must 403-path (verify false).
const tampers = [
  ['wss_url', 'wss://evil.example/ws'],
  ['route_macaroon', 'stolen-secret'],
  ['route_endpoint', 'https://evil.example'],
  ['endpoint', 'https://evil.example'],
  ['name', 'Evil LSP'],
  ['fee_ppm', 1],
  ['supports_jit', false],
  ['ts', body.ts + 1],
];
for (const [k, v] of tampers) {
  const bad = canonicalRegisterMsg({ ...stored, [k]: v });
  t(`tampered ${k} rejected`, !(await verifyLndSignedRegistration(pub, bad, signature)));
}

const otherPub = Buffer.from(secp.getPublicKey(secp.utils.randomPrivateKey(), true)).toString('hex');
t('signature from a different key rejected', !(await verifyLndSignedRegistration(otherPub, workerMsg, signature)));
t('garbage signature rejected', !(await verifyLndSignedRegistration(pub, workerMsg, 'ybndrfg8ybndrfg8')));
t('truncated signature rejected', !(await verifyLndSignedRegistration(pub, workerMsg, signature.slice(0, 100))));
t('non-zbase32 chars rejected', !(await verifyLndSignedRegistration(pub, workerMsg, 'l0v2' + signature.slice(4))));

{ // zbase32 encoder/decoder roundtrip on random 65-byte blobs
  let ok = true;
  for (let i = 0; i < 50; i++) {
    const b = randomBytes(65);
    const d = zbase32Decode(zb32enc(b));
    if (!d || !Buffer.from(d).equals(b)) { ok = false; break; }
  }
  t('zbase32 roundtrip x50', ok);
}

// ── lijox-scb:v1 — the SCB backup canonicals ride the same verify ──────────
{
  const blob = randomBytes(1337);                       // stand-in SCB bytes
  const hash = createHash('sha256').update(blob).digest('hex');
  const ts = Math.floor(Date.now() / 1000);
  const push = canonicalScbPush(pub, ts, hash);
  t('scb push canonical signs and verifies', await verifyLndSignedRegistration(pub, push, lndSign(priv, push)));
  const sigPush = lndSign(priv, push);
  t('scb push: tampered blob hash rejected', !(await verifyLndSignedRegistration(pub, canonicalScbPush(pub, ts, createHash('sha256').update(Buffer.concat([blob, Buffer.from([1])])).digest('hex')), sigPush)));
  t('scb push: tampered ts rejected', !(await verifyLndSignedRegistration(pub, canonicalScbPush(pub, ts + 1, hash), sigPush)));
  t('scb push: other key rejected', !(await verifyLndSignedRegistration(otherPub, push, sigPush)));
  const get = canonicalScbGet(pub, ts);
  t('scb get canonical signs and verifies', await verifyLndSignedRegistration(pub, get, lndSign(priv, get)));
  t('scb get sig does not open push (domains separate)', !(await verifyLndSignedRegistration(pub, push, lndSign(priv, get))));
}

// ── lijox-unregister:v1 (0.6.0) — the departure canonical rides the same verify ─
{
  const ts = Math.floor(Date.now() / 1000);
  const m = canonicalUnregisterMsg(pub, ts);
  t('unregister canonical shape', m === `lijox-unregister:v1:${pub}:${ts}`);
  t('unregister signs and verifies', await verifyLndSignedRegistration(pub, m, lndSign(priv, m)));
  const sig = lndSign(priv, m);
  t('unregister: tampered ts rejected', !(await verifyLndSignedRegistration(pub, canonicalUnregisterMsg(pub, ts + 1), sig)));
  t('unregister: other key rejected', !(await verifyLndSignedRegistration(otherPub, m, sig)));
  t('unregister sig does not open register (domains separate)', !(await verifyLndSignedRegistration(pub, canonicalRegisterMsg({ pubkey: pub, ts }), sig)));
}

// ── 0.8.0 (S52): lijox-register:v2 — a record that offers a block-filter server ─
{
  // a v1 record (no filter_url) signs exactly as the 0.7.0 canonical did — older adapters are unaffected
  const v1Old = (f) => {
    const s = (v) => (v === null || v === undefined) ? '' : String(v);
    const n = (v) => String(Number(v) || 0);
    return 'lijox-register:v1:' + [s(f.pubkey), n(f.ts), s(f.name), s(f.endpoint), s(f.wss_url), s(f.route_endpoint), s(f.route_macaroon),
      n(f.fee_ppm), n(f.fee_base_sats), n(f.channel_open_fee_sats), n(f.max_channel_size_sats), (f.supports_jit ? '1' : '0')].map(encodeURIComponent).join(':');
  };
  t('v1 record: canonical byte-identical to 0.7.0', canonicalRegisterMsg(stored) === v1Old(stored));
  t('v1 record with filter_url null stays v1', canonicalRegisterMsg({ ...stored, filter_url: null, filter_sp: false }) === v1Old(stored));
  // the adapter's v2 body and the worker's stored record
  const b2 = { ...body, filter_url: 'https://filters.example.org', filter_sp: true };
  const m2 = canonicalRegisterMsg(b2);
  const sig2 = lndSign(priv, m2);
  const st2 = { ...stored, ts: Number(b2.ts), filter_url: cleanFilterUrl(b2.filter_url), filter_sp: Boolean(b2.filter_sp) };
  t('v2 canonical prefix', m2.startsWith('lijox-register:v2:') && m2.endsWith(':' + encodeURIComponent('https://filters.example.org') + ':1'));
  t('v2 adapter and worker canonicals are byte-identical', canonicalRegisterMsg(st2) === m2);
  t('v2 signature verifies', await verifyLndSignedRegistration(pub, canonicalRegisterMsg(st2), sig2));
  t('v2: tampered filter_url rejected', !(await verifyLndSignedRegistration(pub, canonicalRegisterMsg({ ...st2, filter_url: 'https://evil.example' }), sig2)));
  t('v2: tampered filter_sp rejected', !(await verifyLndSignedRegistration(pub, canonicalRegisterMsg({ ...st2, filter_sp: false }), sig2)));
  t('v2: stripping filter_url (downgrade to v1) rejected', !(await verifyLndSignedRegistration(pub, canonicalRegisterMsg({ ...st2, filter_url: null }), sig2)));
  t('v1 signature cannot carry an added filter_url', !(await verifyLndSignedRegistration(pub, canonicalRegisterMsg({ ...stored, filter_url: 'https://evil.example', filter_sp: true }), signature)));
  // the address rule (the engine's clean_filter_base, v296)
  t('filter_url absent → null', cleanFilterUrl(undefined) === null && cleanFilterUrl('') === null && cleanFilterUrl(null) === null);
  t('filter_url plain https kept', cleanFilterUrl('https://filters.example.org') === 'https://filters.example.org' && cleanFilterUrl('https://box.example.org:8443/lij/filters') === 'https://box.example.org:8443/lij/filters');
  const bad = ['http://x.org', 'https://x.org/', 'https://', 'https://-x.org', 'https://a b.org', 'https://user@x.org', 'https://x.org?q=1', 'https://x.org/#f', 'https://x.org:port', 'https://x.org:123456', 'javascript:alert(1)', 'https://x.org/"onload', 'https://' + 'a'.repeat(200) + '.org'];
  t('filter_url refused: ' + bad.length + ' bad shapes', bad.every((b) => cleanFilterUrl(b) === undefined));
}

// ── 0.11.0 (S58, Tatara step 4): lijox-register:v3 — a record that offers Tatara pools (spec v0.10 §11.2) ─
{
  const T = {
    v: 1, sizes: [50000, 100000, 250000, 1000000], min_people: 3, max_people: 6, countdown_s: 600, wake_window_s: 180,
    max_retries: 2, strikes: 4, max_pools_per_size: 3, max_pools_total: 10, max_list_per_size: 60, max_fee_rate: 20,
    channel_pools: true, channel_sizes: [250000, 1000000], relay_url: 'wss://lsp.example.org/tatara/relay',
    relay_for_others: true, forward_payouts: true, forward_coin_checks: true, coin_check_url: 'https://filters.example.org/coin',
    ring_hash: 'ab'.repeat(32),
  };
  const ct = cleanTatara(T);
  t('v3: a full block is kept as sent', JSON.stringify(ct) === JSON.stringify(T));
  t('v3: no block → null (v1/v2 records unchanged)', cleanTatara(undefined) === null && cleanTatara(null) === null);
  const st3 = { ...stored, filter_url: 'https://filters.example.org', filter_sp: true, tatara: ct };
  const m3 = canonicalRegisterMsg(st3);
  const sig3 = lndSign(priv, m3);
  t('v3 canonical prefix and field count (12 + 2 + ' + TATARA_FIELDS.length + ')', m3.startsWith('lijox-register:v3:') && m3.split(':').length === 2 + 12 + 2 + TATARA_FIELDS.length);
  t('v3 tail: sizes comma-joined … ring hash last', m3.includes(':1:' + encodeURIComponent('50000,100000,250000,1000000') + ':3:6:600:180:2:4:3:10:60:20:1:' + encodeURIComponent('250000,1000000') + ':') && m3.endsWith(':' + 'ab'.repeat(32)));
  t('v3 signature verifies', await verifyLndSignedRegistration(pub, m3, sig3));
  const alt = { v: 1, sizes: [50000, 100000], min_people: 4, max_people: 5, countdown_s: 601, wake_window_s: 181, max_retries: 3, strikes: 5,
    max_pools_per_size: 4, max_pools_total: 11, max_list_per_size: 61, max_fee_rate: 21, channel_pools: false, channel_sizes: [],
    relay_url: 'wss://evil.example/r', relay_for_others: false, forward_payouts: false, forward_coin_checks: false, coin_check_url: null, ring_hash: 'cd'.repeat(32) };
  let every = true;
  for (const [k] of TATARA_FIELDS) {
    if (k === 'v') continue;
    const tam = { ...ct, [k]: alt[k] };
    if (k === 'channel_pools') tam.channel_sizes = [];
    if (await verifyLndSignedRegistration(pub, canonicalRegisterMsg({ ...st3, tatara: tam }), sig3)) { every = false; console.log('   (not caught: ' + k + ')'); }
  }
  t('v3: every tatara field is under the signature (' + (TATARA_FIELDS.length - 1) + ' tampered, each rejected)', every);
  t('v3: stripping the block (downgrade to v2) rejected', !(await verifyLndSignedRegistration(pub, canonicalRegisterMsg({ ...st3, tatara: undefined }), sig3)));
  t('v2 signature cannot carry an added block', !(await verifyLndSignedRegistration(pub, canonicalRegisterMsg({ ...stored, filter_url: 'https://filters.example.org', filter_sp: true, tatara: ct }), lndSign(priv, canonicalRegisterMsg({ ...stored, filter_url: 'https://filters.example.org', filter_sp: true })))));
  const noFilter = canonicalRegisterMsg({ ...stored, tatara: ct });
  t('v3 without a filter server: filter_url \'\' and filter_sp 0 in place', noFilter.startsWith('lijox-register:v3:') && noFilter.includes(':' + (stored.supports_jit ? '1' : '0') + '::0:1:'));
  const bad = {
    'an unknown key': { ...T, extra: 1 }, 'v 2': { ...T, v: 2 }, 'sizes unsorted': { ...T, sizes: [100000, 50000] },
    'sizes repeated': { ...T, sizes: [50000, 50000] }, 'no sizes': { ...T, sizes: [] }, '13 sizes': { ...T, sizes: Array.from({ length: 13 }, (_, i) => 1000 * (i + 1)) },
    'a size as a string': { ...T, sizes: ['50000'] }, 'a float': { ...T, countdown_s: 600.5 }, 'min > max': { ...T, min_people: 7 },
    'channel sizes with channel pools off': { ...T, channel_pools: false },
    'close sizes unsorted': { ...T, close_sizes: [500000, 400000] }, 'a close size as a string': { ...T, close_sizes: ['400000'] }, '13 close sizes': { ...T, close_sizes: Array.from({ length: 13 }, (_, i) => 1000 * (i + 1)) }, 'close sizes not a list': { ...T, close_sizes: 400000 },
    'channel pools on, no sizes': { ...T, channel_sizes: [] }, 'a ws:// relay': { ...T, relay_url: 'ws://lsp.example.org/r' },
    'an https relay': { ...T, relay_url: 'https://lsp.example.org/r' }, 'no relay': { ...T, relay_url: '' },
    'an http coin check': { ...T, coin_check_url: 'http://x.org/c' }, 'an upper-case ring hash': { ...T, ring_hash: 'AB'.repeat(32) },
    'a short ring hash': { ...T, ring_hash: 'ab' }, 'a boolean as 1': { ...T, forward_payouts: 1 }, 'a list as the block': [1, 2],
    'retries 101': { ...T, max_retries: 101 }, 'fee cap 0': { ...T, max_fee_rate: 0 },
  };
  const missed = Object.entries(bad).filter(([, b]) => cleanTatara(b) !== undefined).map(([k]) => k);
  t('v3: ' + Object.keys(bad).length + ' malformed blocks refused' + (missed.length ? ' — MISSED: ' + missed.join(', ') : ''), missed.length === 0);
  // through the worker's own handler (in-memory KV): a v3 registration stored with its block; a malformed one refused;
  // a v2 registration stored without a tatara key; a v3 record whose block was changed after signing refused
  {
    const kv = new Map();
    const env = { LIJ_KV: { get: async (k) => (kv.has(k) ? kv.get(k) : null), put: async (k, v) => { kv.set(k, v); }, delete: async (k) => { kv.delete(k); }, list: async () => ({ keys: [] }) } };
    const post = async (b) => { const r = await worker.fetch(new Request('https://lij-worker.test/lsps/register', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(b) }), env, {}); let j = null; try { j = await r.json(); } catch (e) {} return { status: r.status, json: j }; };
    const now = Math.floor(Date.now() / 1000);
    const b3 = { ...body, ts: now, filter_url: 'https://filters.example.org', filter_sp: true, tatara: T };
    const rec3 = { name: b3.name, pubkey: b3.pubkey, endpoint: b3.endpoint, fee_ppm: Number(b3.fee_ppm), fee_base_sats: Number(b3.fee_base_sats || 0), channel_open_fee_sats: Number(b3.channel_open_fee_sats || 0),
      max_channel_size_sats: Number(b3.max_channel_size_sats || 0), supports_jit: Boolean(b3.supports_jit), route_endpoint: b3.route_endpoint || null, route_macaroon: b3.route_macaroon || null,
      wss_url: b3.wss_url || null, filter_url: b3.filter_url, filter_sp: true, tatara: cleanTatara(T), ts: now };
    b3.signature = lndSign(priv, canonicalRegisterMsg(rec3));
    let r = await post(b3);
    const kept = kv.get('lsp:' + pub) ? JSON.parse(kv.get('lsp:' + pub)) : null;
    t('v3 through the handler: stored, its block as signed', r.status === 200 && kept && JSON.stringify(kept.tatara) === JSON.stringify(T));
    r = await post({ ...b3, tatara: { ...T, max_fee_rate: 30 } });
    t('v3 through the handler: a block changed after signing → 403', r.status === 403);
    r = await post({ ...b3, tatara: { ...T, sizes: [100000, 50000] } });
    t('v3 through the handler: a malformed block → 400, nothing stored over the good record', r.status === 400 && JSON.parse(kv.get('lsp:' + pub)).tatara.max_fee_rate === 20);
    const b2 = { ...body, ts: now + 1, filter_url: 'https://filters.example.org', filter_sp: true };
    const rec2 = { ...rec3, ts: now + 1 }; delete rec2.tatara;
    b2.signature = lndSign(priv, canonicalRegisterMsg(rec2));
    r = await post(b2);
    t('v2 through the handler: stored with no tatara key (a provider that stops offering pools drops the block)', r.status === 200 && !('tatara' in JSON.parse(kv.get('lsp:' + pub))));
  }
  t('v3: no coin check and no ring yet → null, null', (() => { const c = cleanTatara({ ...T, coin_check_url: '', ring_hash: null }); return c && c.coin_check_url === null && c.ring_hash === null; })());
  // ── 0.12.0 / 0.12.1 (S59, DP item 20): the channel list is the provider's own; close_sizes came and went the same day ──
  t('0.12.0: a channel size outside the on-chain sizes is allowed (the lists are the provider\'s own)', cleanTatara({ ...T, channel_sizes: [500000] }) !== undefined);
  t('0.12.1: close_sizes is an unknown key — refused (no v4; the v3 message is 0.11.0\'s, byte for byte)', cleanTatara({ ...T, close_sizes: [400000] }) === undefined && cleanTatara({ ...T, close_sizes: [] }) === undefined && canonicalRegisterMsg(st3) === m3 && m3.startsWith('lijox-register:v3:'));
  t('0.12.1: TATARA_FIELDS has no close_sizes', !TATARA_FIELDS.some(([k]) => k === 'close_sizes'));
  {
    const kv = new Map();
    const env = { LIJ_KV: { get: async (k) => (kv.has(k) ? kv.get(k) : null), put: async (k, v) => { kv.set(k, v); }, delete: async (k) => { kv.delete(k); }, list: async () => ({ keys: [] }) } };
    const post = async (b) => { const r = await worker.fetch(new Request('https://lij-worker.test/lsps/register', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(b) }), env, {}); let j = null; try { j = await r.json(); } catch (e) {} return { status: r.status, json: j }; };
    const now = Math.floor(Date.now() / 1000);
    const Tc = { ...T, channel_sizes: [500000] };
    const bc = { ...body, ts: now, filter_url: 'https://filters.example.org', filter_sp: true, tatara: Tc };
    const recc = { name: bc.name, pubkey: bc.pubkey, endpoint: bc.endpoint, fee_ppm: Number(bc.fee_ppm), fee_base_sats: Number(bc.fee_base_sats || 0), channel_open_fee_sats: Number(bc.channel_open_fee_sats || 0),
      max_channel_size_sats: Number(bc.max_channel_size_sats || 0), supports_jit: Boolean(bc.supports_jit), route_endpoint: bc.route_endpoint || null, route_macaroon: bc.route_macaroon || null,
      wss_url: bc.wss_url || null, filter_url: bc.filter_url, filter_sp: true, tatara: cleanTatara(Tc), ts: now };
    bc.signature = lndSign(priv, canonicalRegisterMsg(recc));
    let r = await post(bc);
    t('0.12.0 through the handler: a channel size outside the on-chain sizes is stored', r.status === 200 && JSON.stringify(JSON.parse(kv.get('lsp:' + pub)).tatara.channel_sizes) === '[500000]');
    r = await post({ ...bc, tatara: { ...Tc, close_sizes: [400000] } });
    t('0.12.1 through the handler: a block with close_sizes → 400 (unknown key)', r.status === 400);
  }
}


// ── 0.13.0 (S61, Step A): lijox-register:v4 — a record that carries a routes list (routes-r1 §2) ─────────────────────
{
  const R = [
    { reach: 'direct', endpoint: 'https://direct-lsp.example.org', wss_url: 'wss://direct-ws.example.org', filter_url: 'https://direct-filters.example.org' },
    { reach: 'cloudflare', endpoint: 'https://lsp.example.org', wss_url: 'wss://ws.example.org', filter_url: 'https://filters.example.org' },
  ];
  const cr = cleanRoutes(R);
  t('v4: a two-route list is kept as sent', JSON.stringify(cr) === JSON.stringify(R));
  t('v4: no list → null (v1/v2/v3 records unchanged)', cleanRoutes(undefined) === null && cleanRoutes(null) === null);
  t('v4: a route without a filter server reads null', (() => { const c = cleanRoutes([{ ...R[0], filter_url: '' }]); return c && c[0].filter_url === null; })());
  t('v4: the three reach words', JSON.stringify(ROUTE_REACH) === '["direct","cloudflare","tor"]');
  // the stored record: the top-level addresses are route 1's (the handler enforces it)
  const st4 = { ...stored, endpoint: R[0].endpoint, wss_url: R[0].wss_url, filter_url: R[0].filter_url, filter_sp: true, routes: cr };
  const m4 = canonicalRegisterMsg(st4);
  const sig4 = lndSign(priv, m4);
  t('v4 canonical prefix and field count (12 + 2 + ' + TATARA_FIELDS.length + ' + 1)', m4.startsWith('lijox-register:v4:') && m4.split(':').length === 2 + 12 + 2 + TATARA_FIELDS.length + 1);
  const rf = encodeURIComponent(R.map((r) => [r.reach, r.endpoint, r.wss_url, r.filter_url].join('|')).join(';'));
  t('v4 tail: the routes as one percent-encoded field, last', m4.endsWith(':' + rf) && rf.includes('%7C') && rf.includes('%3B'));
  const T0 = TATARA_FIELDS.map(([, kind]) => kind === 'list' ? '' : kind === 'str' ? '' : '0').join(':');
  t('v4 without a tatara block: every block field in place as \'\' / \'0\'', m4.includes(':' + encodeURIComponent(R[0].filter_url) + ':1:' + T0 + ':' + rf));
  t('v4 signature verifies', await verifyLndSignedRegistration(pub, m4, sig4));
  const tampers = [
    ['reach of route 1', (x) => ({ ...x, routes: [{ ...x.routes[0], reach: 'cloudflare' }, x.routes[1]] })],
    ['endpoint of route 2', (x) => ({ ...x, routes: [x.routes[0], { ...x.routes[1], endpoint: 'https://evil.example' }] })],
    ['wss_url of route 2', (x) => ({ ...x, routes: [x.routes[0], { ...x.routes[1], wss_url: 'wss://evil.example' }] })],
    ['filter_url of route 1', (x) => ({ ...x, routes: [{ ...x.routes[0], filter_url: 'https://evil.example' }, x.routes[1]] })],
    ['a route dropped', (x) => ({ ...x, routes: [x.routes[0]] })],
    ['a route added', (x) => ({ ...x, routes: x.routes.concat([{ reach: 'tor', endpoint: 'https://t.example.org', wss_url: 'wss://t.example.org', filter_url: null }]) })],
    ['the routes swapped', (x) => ({ ...x, routes: [x.routes[1], x.routes[0]] })],
    ['the list stripped (downgrade to v2)', (x) => ({ ...x, routes: undefined })],
  ];
  let every = true;
  for (const [name, f] of tampers) {
    if (await verifyLndSignedRegistration(pub, canonicalRegisterMsg(f(st4)), sig4)) { every = false; console.log('   (not caught: ' + name + ')'); }
  }
  t('v4: every route field, count and order is under the signature (' + tampers.length + ' tampered, each rejected)', every);
  t('v2 signature cannot carry an added routes list', !(await verifyLndSignedRegistration(pub, canonicalRegisterMsg({ ...st4, filter_sp: true }), lndSign(priv, canonicalRegisterMsg({ ...st4, routes: undefined })))));
  // with a tatara block too: v4 carries the block's fields before the routes
  const T4 = { v: 1, sizes: [50000, 100000], min_people: 3, max_people: 6, countdown_s: 600, wake_window_s: 180, max_retries: 2, strikes: 4, max_pools_per_size: 3,
    max_pools_total: 10, max_list_per_size: 60, max_fee_rate: 20, channel_pools: true, channel_sizes: [100000], relay_url: 'wss://lsp.example.org/tatara/relay',
    relay_for_others: true, forward_payouts: true, forward_coin_checks: true, coin_check_url: 'https://filters.example.org/coin', ring_hash: 'ab'.repeat(32) };
  const st4t = { ...st4, tatara: cleanTatara(T4) };
  const m4t = canonicalRegisterMsg(st4t);
  t('v4 with a tatara block: prefix v4, the block then the routes', m4t.startsWith('lijox-register:v4:') && m4t.includes(':' + encodeURIComponent('50000,100000') + ':3:6:') && m4t.endsWith(':' + 'ab'.repeat(32) + ':' + rf));
  t('v4 with a block: a tampered block field rejected', !(await verifyLndSignedRegistration(pub, canonicalRegisterMsg({ ...st4t, tatara: { ...st4t.tatara, max_fee_rate: 21 } }), lndSign(priv, m4t))));
  const bad = {
    'an empty list': [], 'four routes': [R[0], R[1], { ...R[0], endpoint: 'https://a.example.org' }, { ...R[0], endpoint: 'https://b.example.org' }],
    'an unknown word': [{ ...R[0], reach: 'vpn' }], 'no reach': [{ endpoint: R[0].endpoint, wss_url: R[0].wss_url, filter_url: null }],
    'an extra key': [{ ...R[0], note: 'x' }], 'an http endpoint': [{ ...R[0], endpoint: 'http://x.example.org' }],
    'a trailing slash': [{ ...R[0], endpoint: 'https://x.example.org/' }], 'no endpoint': [{ ...R[0], endpoint: '' }],
    'a ws:// link': [{ ...R[0], wss_url: 'ws://x.example.org' }], 'no wss_url': [{ ...R[0], wss_url: '' }],
    'an http filter_url': [{ ...R[0], filter_url: 'http://x.example.org' }], 'two routes, one endpoint': [R[0], { ...R[1], endpoint: R[0].endpoint }],
    'a string as the list': 'direct', 'an object as the list': { reach: 'direct' }, 'a route that is a list': [[1, 2]],
  };
  const missed = Object.entries(bad).filter(([, b]) => cleanRoutes(b) !== undefined).map(([k]) => k);
  t('v4: ' + Object.keys(bad).length + ' malformed lists refused' + (missed.length ? ' — MISSED: ' + missed.join(', ') : ''), missed.length === 0);
  // through the handler (in-memory KV): stored with its routes; routes[0] not repeating the record's addresses → 400;
  // a route changed after signing → 403; a one-door record stores with no routes key; GET /lsps serves routes as stored
  {
    const kv = new Map();
    const env = { LIJ_KV: { get: async (k) => (kv.has(k) ? kv.get(k) : null), put: async (k, v) => { kv.set(k, v); }, delete: async (k) => { kv.delete(k); }, list: async () => ({ keys: Array.from(kv.keys()).filter((k) => k.startsWith('lsp:')).map((name) => ({ name })) }) } };
    const post = async (b) => { const r = await worker.fetch(new Request('https://lij-worker.test/lsps/register', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(b) }), env, {}); let j = null; try { j = await r.json(); } catch (e) {} return { status: r.status, json: j }; };
    const now = Math.floor(Date.now() / 1000);
    const b4 = { ...body, ts: now, endpoint: R[0].endpoint, route_endpoint: R[0].endpoint, wss_url: R[0].wss_url, filter_url: R[0].filter_url, filter_sp: true, routes: R };
    const rec4 = { name: b4.name, pubkey: b4.pubkey, endpoint: b4.endpoint, fee_ppm: Number(b4.fee_ppm), fee_base_sats: 0, channel_open_fee_sats: 0, max_channel_size_sats: 0,
      supports_jit: Boolean(b4.supports_jit), route_endpoint: b4.route_endpoint, route_macaroon: b4.route_macaroon, wss_url: b4.wss_url, filter_url: b4.filter_url, filter_sp: true, routes: cleanRoutes(R), ts: now };
    b4.signature = lndSign(priv, canonicalRegisterMsg(rec4));
    let r = await post(b4);
    const kept = kv.get('lsp:' + pub) ? JSON.parse(kv.get('lsp:' + pub)) : null;
    t('v4 through the handler: stored, its routes as signed', r.status === 200 && kept && JSON.stringify(kept.routes) === JSON.stringify(R));
    r = await post({ ...b4, routes: [{ ...R[0], reach: 'cloudflare' }, R[1]] });
    t('v4 through the handler: a route changed after signing → 403', r.status === 403);
    r = await post({ ...b4, routes: [R[1], R[0]] });
    t('v4 through the handler: routes[0] not the record\'s own addresses → 400', r.status === 400 && /routes\[0\]/.test(r.json && r.json.error || ''));
    r = await post({ ...b4, routes: [{ ...R[0], reach: 'vpn' }] });
    t('v4 through the handler: a malformed list → 400, the good record untouched', r.status === 400 && JSON.parse(kv.get('lsp:' + pub)).routes.length === 2);
    const g = await worker.fetch(new Request('https://lij-worker.test/lsps'), env, {});
    const gl = (await g.json()).lsps;
    t('GET /lsps serves the routes as stored (signature and ts stripped as before)', g.status === 200 && gl.length === 1 && JSON.stringify(gl[0].routes) === JSON.stringify(R) && !('signature' in gl[0]) && !('ts' in gl[0]));
    const b3 = { ...body, ts: now + 1, filter_url: 'https://filters.example.org', filter_sp: true };
    const rec3 = { ...rec4, ts: now + 1, endpoint: b3.endpoint, route_endpoint: b3.route_endpoint, wss_url: b3.wss_url, filter_url: b3.filter_url }; delete rec3.routes;
    b3.signature = lndSign(priv, canonicalRegisterMsg(rec3));
    r = await post(b3);
    t('a one-door record through the handler: stored with no routes key (an older adapter re-registering drops the list)', r.status === 200 && !('routes' in JSON.parse(kv.get('lsp:' + pub))));
  }
}

console.log(`\n${pass} passed, ${fail} failed`);
process.exit(fail ? 1 : 0);
