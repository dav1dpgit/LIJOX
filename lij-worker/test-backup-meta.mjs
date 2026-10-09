// 0.9.0 (S57, DP 2026-10-07 "Go with … 1") — POST /backup/meta: the cloud copy's number and date only.
// 0.10.0 (S57, DP 2026-10-08 14:40 "Go") — the copy's fingerprint kept and answered; the same copy sent again is ok (b8–b13).
// Run: node test-backup-meta.mjs   (CI runs it before deploy; a red here blocks)
// Drives the worker's own fetch handler with an in-memory KV and a wallet key signing the same digest the engine signs
// (sha256("lij-backup-v1" || "backup-read" || nonce || pubkey), compact 64-byte ECDSA).
import * as secp from '@noble/secp256k1';
import { createHmac, createHash, randomBytes } from 'node:crypto';
import worker from './src/index.js';

secp.etc.hmacSha256Sync = (key, ...msgs) => { const h = createHmac('sha256', Buffer.from(key)); for (const m of msgs) h.update(Buffer.from(m)); return new Uint8Array(h.digest()); };
let fails = 0;
const ok = (m) => console.log('  ok · ' + m);
const check = (c, m) => { if (!c) { fails++; console.log('FAIL · ' + m); } else ok(m); };
const hex = (b) => Buffer.from(b).toString('hex');

const store = new Map();
const env = { LIJ_KV: {
  get: async (k) => (store.has(k) ? store.get(k) : null),
  put: async (k, v) => { store.set(k, v); },
  delete: async (k) => { store.delete(k); },
  list: async () => ({ keys: [] }),
} };
const priv = randomBytes(32), pub = hex(secp.getPublicKey(priv, true));
const other = randomBytes(32);
const call = async (method, path, body) => {
  const r = await worker.fetch(new Request('https://lij-worker.test' + path, { method, headers: { 'Content-Type': 'application/json' }, body: body ? JSON.stringify(body) : undefined }), env, {});
  let j = null; try { j = await r.json(); } catch (e) {}
  return { status: r.status, json: j };
};
const digest = (action, nonce, pk) => createHash('sha256').update(Buffer.concat([Buffer.from('lij-backup-v1'), Buffer.from(action), Buffer.from(nonce, 'hex'), Buffer.from(pk, 'hex')])).digest();
const signed = async (action, key = priv) => {
  const c = await call('GET', '/backup/challenge?pubkey=' + pub);
  const sig = secp.sign(digest(action, c.json.nonce, pub), key);
  return { pubkey_hex: pub, nonce: c.json.nonce, signature: hex(sig.toCompactRawBytes()) };
};

// b1 — no copy: 200 {found:false} (a 404 would mean the route is missing)
let r = await call('POST', '/backup/meta', await signed('backup-read'));
check(r.status === 200 && r.json && r.json.found === false, 'b1 no copy held: 200 {found:false}');
// b2 — a copy held: its number and date only, never the sealed copy
store.set('backup:' + pub, JSON.stringify({ pubkey_hex: pub, version: 7, saved_at_ms: 1791307311302, encrypted_data: 'ab'.repeat(5000) }));
r = await call('POST', '/backup/meta', await signed('backup-read'));
check(r.status === 200 && r.json.found === true && r.json.version === 7 && r.json.saved_at_ms === 1791307311302, 'b2 found: version 7 and the date');
check(JSON.stringify(Object.keys(r.json).sort()) === JSON.stringify(['fingerprint', 'found', 'saved_at_ms', 'version']), 'b2 nothing else in the answer (no blob; 0.10.0: the fingerprint, null for this copy)');
// b3 — the challenge is single-use
const once = await signed('backup-read');
await call('POST', '/backup/meta', once);
r = await call('POST', '/backup/meta', once);
check(r.status === 401, 'b3 a used challenge is refused (401)');
// b4 — another key's signature is refused
r = await call('POST', '/backup/meta', await signed('backup-read', other));
check(r.status === 401, 'b4 another key\'s signature: 401');
// b5 — a signature for another action is refused
r = await call('POST', '/backup/meta', await signed('backup-push'));
check(r.status === 401, 'b5 a push signature does not read the number: 401');
// b6 — an old copy with no date reads 0 (the wallet shows "date unknown")
store.set('backup:' + pub, JSON.stringify({ pubkey_hex: pub, version: 3, encrypted_data: 'cd' }));
r = await call('POST', '/backup/meta', await signed('backup-read'));
check(r.json.found === true && r.json.version === 3 && r.json.saved_at_ms === 0, 'b6 a copy saved before v309: saved_at_ms 0');
// b7 — the version on /health
r = await call('GET', '/health');
check(r.json && r.json.version === '0.10.0', 'b7 /health says 0.10.0');

// 0.10.0 (S57, DP 2026-10-08 14:40 "Go" on the cloud-copy fingerprint)
// b8 — a push keeps the copy's fingerprint (sha256 of its sealed bytes) and /backup/meta answers it
store.delete('backup:' + pub);
const bytes = (seed, n) => Array.from({ length: n }, (_, i) => (seed * 31 + i * 7) & 255);
const sha = (arr) => createHash('sha256').update(Buffer.from(arr)).digest('hex');
const blobA = { version: 10, encrypted_data: bytes(1, 5000), nonce: [], pubkey_hex: pub, saved_at_ms: 1791307311302 };
r = await call('POST', '/backup', Object.assign(await signed('backup-push'), { blob: blobA }));
check(r.status === 200 && r.json.ok === true && r.json.version === 10 && r.json.fingerprint === sha(blobA.encrypted_data) && !r.json.repeat, 'b8 a push answers ok with the copy\'s fingerprint (sha256 of its sealed bytes)');
r = await call('POST', '/backup/meta', await signed('backup-read'));
check(r.json.found === true && r.json.version === 10 && r.json.saved_at_ms === 1791307311302 && r.json.fingerprint === sha(blobA.encrypted_data), 'b8 /backup/meta answers the number, the date and the fingerprint');
check(JSON.stringify(Object.keys(r.json).sort()) === JSON.stringify(['fingerprint', 'found', 'saved_at_ms', 'version']), 'b8 nothing else in the answer (no blob)');
// b9 — a resend of the very same copy (the phone\'s OK was lost) is an OK again, not a refusal; the copy is unchanged
const before = store.get('backup:' + pub);
r = await call('POST', '/backup', Object.assign(await signed('backup-push'), { blob: blobA }));
check(r.status === 200 && r.json.ok === true && r.json.repeat === true && r.json.version === 10 && store.get('backup:' + pub) === before, 'b9 the same copy sent again: ok (repeat), the stored copy unchanged');
// b10 — the same number with other bytes is another copy: refused as before
const blobB = Object.assign({}, blobA, { encrypted_data: bytes(2, 5000) });
r = await call('POST', '/backup', Object.assign(await signed('backup-push'), { blob: blobB }));
check(r.status === 409 && /existing v10 >= incoming v10/.test(r.json.error), 'b10 the same number with other bytes: 409 as before');
// b11 — a newer number lands and carries its own fingerprint; the fetch returns the copy with it (an extra field the engine ignores)
const blobC = Object.assign({}, blobB, { version: 11 });
r = await call('POST', '/backup', Object.assign(await signed('backup-push'), { blob: blobC }));
check(r.status === 200 && r.json.fingerprint === sha(blobC.encrypted_data), 'b11 the next number is stored with its fingerprint');
r = await call('POST', '/backup/fetch', await signed('backup-read'));
check(r.json.found === true && r.json.blob.version === 11 && r.json.blob.fingerprint === sha(blobC.encrypted_data) && JSON.stringify(r.json.blob.encrypted_data) === JSON.stringify(blobC.encrypted_data), 'b11 the fetched copy carries the fingerprint beside its bytes');
// b12 — a copy stored before 0.10.0 has no fingerprint: meta says null; a same-number resend against it is refused
store.set('backup:' + pub, JSON.stringify({ pubkey_hex: pub, version: 12, saved_at_ms: 5, encrypted_data: bytes(3, 100) }));
r = await call('POST', '/backup/meta', await signed('backup-read'));
check(r.json.found === true && r.json.version === 12 && r.json.fingerprint === null, 'b12 a copy stored before 0.10.0: fingerprint null');
r = await call('POST', '/backup', Object.assign(await signed('backup-push'), { blob: Object.assign({}, blobA, { version: 12, encrypted_data: bytes(3, 100) }) }));
check(r.status === 409, 'b12 the same number against a copy without a fingerprint: refused (nothing to match)');
// b13 — a copy with no byte array is stored as before, with no fingerprint
r = await call('POST', '/backup', Object.assign(await signed('backup-push'), { blob: { version: 13, encrypted_data: 'not-bytes', pubkey_hex: pub } }));
check(r.status === 200 && r.json.ok === true && r.json.fingerprint === null, 'b13 a copy without a byte array: stored, no fingerprint');
console.log(fails ? 'FAIL · backup-meta · ' + fails + ' failed' : 'PASS · backup-meta (b1–b13)');
process.exit(fails ? 1 : 0);
