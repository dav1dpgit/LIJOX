// test-round6.mjs — lij-worker 0.18.0 (S64, Kimi K3.1 Pro round 2, K6a — engine v358): the push's proof binds the copy.
// A v2 push (auth_v 2) is verified over sha256("lij-backup-v2" || "backup-push" || nonce || pubkey || fingerprint ||
// version); a copy or a number swapped after signing is refused; a v1 push (an engine before v358) is still taken this
// one release; the reads keep v1. The vector pinned here is the engine's (lij-core storage::v358_backup_digest_v2_tests).
// Run: node test-round6.mjs   (CI runs it before the deploy; a red here blocks)
import * as secp from '@noble/secp256k1';
import { createHmac, createHash, randomBytes } from 'node:crypto';
import worker from './src/index.js';

secp.etc.hmacSha256Sync = (key, ...msgs) => { const h = createHmac('sha256', Buffer.from(key)); for (const m of msgs) h.update(Buffer.from(m)); return new Uint8Array(h.digest()); };
let fails = 0;
const ok = (m) => console.log('  ok · ' + m);
const check = (c, m, extra) => { if (!c) { fails++; console.log('FAIL · ' + m + (extra !== undefined ? ' — ' + JSON.stringify(extra).slice(0, 300) : '')); } else ok(m); };
const hex = (b) => Buffer.from(b).toString('hex');

const store = new Map();
const env = { LIJ_KV: {
  get: async (k) => (store.has(k) ? store.get(k) : null),
  put: async (k, v) => { store.set(k, v); },
  delete: async (k) => { store.delete(k); },
  list: async () => ({ keys: [] }),
} };
const priv = randomBytes(32), pub = hex(secp.getPublicKey(priv, true));
const call = async (method, path, body, headers) => {
  const r = await worker.fetch(new Request('https://lij-worker.test' + path, { method, headers: Object.assign({ 'Content-Type': 'application/json' }, headers || {}), body: body ? JSON.stringify(body) : undefined }), env, {});
  let j = null; try { j = await r.json(); } catch (e) {}
  return { status: r.status, json: j };
};
const be64 = (n) => { const b = Buffer.alloc(8); b.writeBigUInt64BE(BigInt(n)); return b; };
const digestV1 = (action, nonce, pk) => createHash('sha256').update(Buffer.concat([Buffer.from('lij-backup-v1'), Buffer.from(action), Buffer.from(nonce, 'hex'), Buffer.from(pk, 'hex')])).digest();
const digestV2 = (action, nonce, pk, fp, version) => createHash('sha256').update(Buffer.concat([Buffer.from('lij-backup-v2'), Buffer.from(action), Buffer.from(nonce, 'hex'), Buffer.from(pk, 'hex'), Buffer.from(fp, 'hex'), be64(version)])).digest();
const bytes = (fill, n) => Array.from({ length: n }, () => fill);
const fpOf = (blob) => createHash('sha256').update(Buffer.from(blob.encrypted_data)).digest('hex');
const chal = async () => (await call('GET', '/backup/challenge?pubkey=' + pub)).json.nonce;
const signedV2 = async (blob) => { const nonce = await chal(); return { pubkey_hex: pub, nonce, signature: hex(secp.sign(digestV2('backup-push', nonce, pub, fpOf(blob), blob.version), priv).toCompactRawBytes()), auth_v: 2, blob }; };
const signedV1 = async (blob) => { const nonce = await chal(); return { pubkey_hex: pub, nonce, signature: hex(secp.sign(digestV1('backup-push', nonce, pub), priv).toCompactRawBytes()), blob }; };

// the pinned vector — the engine's (nonce 00×32, pubkey 02 03×32, fingerprint 11×32, version 7)
check(digestV2('backup-push', '00'.repeat(32), '02' + '03'.repeat(32), '11'.repeat(32), 7).toString('hex') === '53d153264315f77bb76b94af0ac8c3ace02cb3aae47fbaa5c9fa680e703da2fd', 'k6a the v2 digest\'s pinned vector (lij-core storage::v358_backup_digest_v2_tests carries the same)');

// a v2 push
const blobA = { pubkey_hex: pub, version: 1, saved_at_ms: Date.now(), encrypted_data: bytes(1, 64) };
let r = await call('POST', '/backup', await signedV2(blobA));
check(r.status === 200 && r.json.ok === true && r.json.version === 1 && r.json.fingerprint === fpOf(blobA), 'k6a a v2 push signed over its own copy and number is stored', r);
// the copy swapped after signing
const env2 = await signedV2(Object.assign({}, blobA, { version: 2 }));
env2.blob = Object.assign({}, blobA, { version: 2, encrypted_data: bytes(9, 64) });
r = await call('POST', '/backup', env2);
check(r.status === 401, 'k6a a copy swapped after signing (v2) is refused', r);
// the number swapped after signing
const env3 = await signedV2(Object.assign({}, blobA, { version: 2 }));
env3.blob = Object.assign({}, blobA, { version: 3 });
r = await call('POST', '/backup', env3);
check(r.status === 401, 'k6a a number changed after signing (v2) is refused', r);
check(JSON.parse(store.get('backup:' + pub)).version === 1, 'k6a the stored copy is still number 1 after the two refusals');
// a v2 proof presented as v1 and a v1 proof presented as v2 are both refused
const asV1 = await signedV2(Object.assign({}, blobA, { version: 2 })); delete asV1.auth_v;
r = await call('POST', '/backup', asV1);
check(r.status === 401, 'k6a a v2 signature without auth_v is checked as v1 and refused', r);
const asV2 = await signedV1(Object.assign({}, blobA, { version: 2 })); asV2.auth_v = 2;
r = await call('POST', '/backup', asV2);
check(r.status === 401, 'k6a a v1 signature claiming auth_v 2 is refused', r);
// a v2 push of a copy with no byte array cannot be bound
r = await call('POST', '/backup', Object.assign(await signedV2(Object.assign({}, blobA, { version: 2 })), { blob: { pubkey_hex: pub, version: 2, encrypted_data: 'not-bytes' } }));
check(r.status === 400, 'k6a a v2 push whose copy carries no byte array is refused (400)', r);
// auth_v neither 1 nor 2
r = await call('POST', '/backup', Object.assign(await signedV2(Object.assign({}, blobA, { version: 2 })), { auth_v: 3 }));
check(r.status === 400, 'k6a auth_v 3 is refused (400)', r);
// a v1 push is still taken this release
r = await call('POST', '/backup', await signedV1(Object.assign({}, blobA, { version: 2 })));
check(r.status === 200 && r.json.version === 2, 'k6a a v1 push (an engine before v358) is still taken this one release', r);
// the reads keep v1
const nonceR = await chal();
r = await call('POST', '/backup/meta', { pubkey_hex: pub, nonce: nonceR, signature: hex(secp.sign(digestV1('backup-read', nonceR, pub), priv).toCompactRawBytes()) });
check(r.status === 200 && r.json.found === true && r.json.version === 2, 'k6a the meta read keeps the v1 proof', r);
// the version on /health
r = await call('GET', '/health');
check(r.json && r.json.version === '0.18.0', 'k6a /health says 0.18.0', r.json);

console.log('\n' + (fails ? 'FAIL · ' + fails : 'PASS · test-round6 (0.18.0 — K6a: the push\'s proof binds the copy)'));
process.exit(fails ? 1 : 0);
