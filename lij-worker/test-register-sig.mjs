// S41 register-signature fix — sign↔verify gate. Run: node test-register-sig.mjs
//
// Simulates the ADAPTER/LND side byte-for-byte (LND signmessage: compact
// recoverable ECDSA over dsha256('Lightning Signed Message:' + msg), header
// byte 27+4+recId, zbase32) and verifies with the WORKER'S ACTUAL functions
// imported from src/index.js — so a canonical-string or format mismatch
// cannot reach deploy. CI runs this before wrangler; a red here blocks.
import * as secp from '@noble/secp256k1';
import { createHmac, createHash, randomBytes } from 'node:crypto';
import { canonicalRegisterMsg, verifyLndSignedRegistration, zbase32Decode, canonicalScbPush, canonicalScbGet } from './src/index.js';

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

console.log(`\n${pass} passed, ${fail} failed`);
process.exit(fail ? 1 : 0);
