// test-round9.mjs — lij-worker 0.23.0 (S71 Fri 2026-11-20, DP 09:37 "a record of the attempt and confirmations should be
// kept and self healing achieved, on either side of the flow (cloud and local)"; incident
// docs/incidents/2026-11-20-channel-close-r2.md — engine v381 reads it):
//   · a refused upload NAMES the copy the registry holds (number, fingerprint, date); the words of the refusal unchanged
//   · the registry keeps its own record of the last 8 uploads it accepted (number, fingerprint, the registry's clock),
//     inside the copy's entry, written by the registry only; /backup/meta answers it to the wallet's own key
// Run: node test-round9.mjs   (CI runs it before the deploy; a red here blocks)
import * as secp from '@noble/secp256k1';
import { createHmac, createHash, randomBytes } from 'node:crypto';
import worker from './src/index.js';

secp.etc.hmacSha256Sync = (key, ...msgs) => { const h = createHmac('sha256', Buffer.from(key)); for (const m of msgs) h.update(Buffer.from(m)); return new Uint8Array(h.digest()); };
let fails = 0;
const ok = (m) => console.log('  ok · ' + m);
const check = (c, m, extra) => { if (!c) { fails++; console.log('FAIL · ' + m + (extra !== undefined ? ' — ' + JSON.stringify(extra).slice(0, 400) : '')); } else ok(m); };
const hex = (b) => Buffer.from(b).toString('hex');
const store = new Map();
const env = { LIJ_KV: {
  get: async (k) => (store.has(k) ? store.get(k) : null),
  put: async (k, v) => { store.set(k, v); },
  delete: async (k) => { store.delete(k); },
  list: async () => ({ keys: [] }),
} };
const priv = randomBytes(32), pub = hex(secp.getPublicKey(priv, true));
const call = async (method, path, body) => {
  const r = await worker.fetch(new Request('https://lij-worker.test' + path, { method, headers: { 'Content-Type': 'application/json' }, body: body ? JSON.stringify(body) : undefined }), env, {});
  let j = null; try { j = await r.json(); } catch (e) {}
  return { status: r.status, json: j };
};
const be64 = (n) => { const b = Buffer.alloc(8); b.writeBigUInt64BE(BigInt(n)); return b; };
const digestV1 = (action, nonce, pk) => createHash('sha256').update(Buffer.concat([Buffer.from('lij-backup-v1'), Buffer.from(action), Buffer.from(nonce, 'hex'), Buffer.from(pk, 'hex')])).digest();
const digestV2 = (action, nonce, pk, fp, version) => createHash('sha256').update(Buffer.concat([Buffer.from('lij-backup-v2'), Buffer.from(action), Buffer.from(nonce, 'hex'), Buffer.from(pk, 'hex'), Buffer.from(fp, 'hex'), be64(version)])).digest();
const bytes = (fill, n) => Array.from({ length: n }, () => fill);
const fpOf = (blob) => createHash('sha256').update(Buffer.from(blob.encrypted_data)).digest('hex');
const chal = async () => (await call('GET', '/backup/challenge?pubkey=' + pub)).json.nonce;
const push = async (blob) => { const nonce = await chal(); return call('POST', '/backup', { pubkey_hex: pub, nonce, signature: hex(secp.sign(digestV2('backup-push', nonce, pub, fpOf(blob), blob.version), priv).toCompactRawBytes()), auth_v: 2, blob }); };
const read = async (path) => { const nonce = await chal(); return call('POST', path, { pubkey_hex: pub, nonce, signature: hex(secp.sign(digestV1('backup-read', nonce, pub), priv).toCompactRawBytes()) }); };
const copy = (version, fill, extra) => Object.assign({ pubkey_hex: pub, version, saved_at_ms: 1795000000000 + version, encrypted_data: bytes(fill, 64) }, extra || {});
const t0 = Date.now();

// r1 — a copy stored before 0.23.0 (no record): the number check answers an empty record
store.set('backup:' + pub, JSON.stringify(Object.assign(copy(7312, 1), { fingerprint: fpOf(copy(7312, 1)) })));
let r = await read('/backup/meta');
check(r.status === 200 && r.json.found === true && Array.isArray(r.json.accepted) && r.json.accepted.length === 0, 'r1 a copy stored before 0.23.0: /backup/meta answers accepted: []', r);

// r2 — an accepted upload joins the record: number, fingerprint, the registry's clock
const A = copy(7313, 2);
r = await push(A);
check(r.status === 200 && r.json.ok === true, 'r2 the upload no. 7313 is accepted', r);
r = await read('/backup/meta');
check(r.json.accepted.length === 1 && r.json.accepted[0].v === 7313 && r.json.accepted[0].fp === fpOf(A) && r.json.accepted[0].at >= t0 && r.json.accepted[0].at <= Date.now(), 'r2 the record: no. 7313, its fingerprint, the registry\'s own clock (not the phone\'s date)', r.json);

// r3 — THE INCIDENT: no. 7314 is stored (the phone never gets the answer); the phone's next upload is new bytes under
// the same number. The refusal names the copy held.
const B = copy(7314, 3), C = copy(7314, 4);
r = await push(B);
check(r.status === 200, 'r3 the upload no. 7314 is stored (its answer is the one the phone never received)', r);
r = await push(C);
check(r.status === 409 && r.json.error === 'Stale backup rejected: existing v7314 >= incoming v7314', 'r3 new bytes under the same number: refused, the words unchanged (engines before v381 read them)', r);
check(r.json.existing_version === 7314 && r.json.existing_fingerprint === fpOf(B) && r.json.existing_saved_at_ms === B.saved_at_ms, 'r3 the refusal names the copy held: its number, its fingerprint (the FIRST upload\'s — the phone can see it is its own), its date', r.json);
check(JSON.stringify(Object.keys(r.json).sort()) === JSON.stringify(['error', 'existing_fingerprint', 'existing_saved_at_ms', 'existing_version']), 'r3 nothing else in the refusal');
r = await read('/backup/meta');
check(r.json.version === 7314 && r.json.fingerprint === fpOf(B) && r.json.accepted.length === 2, 'r3 the refused copy changed nothing: the copy held and the record are as before', r.json);

// r4 — the phone, having seen that the copy held is its own, sends the new bytes as the next number
const C2 = copy(7315, 4);
r = await push(C2);
check(r.status === 200 && r.json.version === 7315, 'r4 the same bytes as no. 7315: accepted', r);
r = await read('/backup/meta');
const acc = r.json.accepted;
check(JSON.stringify(acc.map((e) => [e.v, e.fp])) === JSON.stringify([[7313, fpOf(A)], [7314, fpOf(B)], [7315, fpOf(C2)]]) && acc[0].at <= acc[1].at && acc[1].at <= acc[2].at, 'r4 the record now reads 7313, 7314, 7315 in the order they were accepted — the upload whose answer was lost is in it', acc);

// r5 — the very same copy sent again is an OK and adds nothing to the record
r = await push(C2);
check(r.status === 200 && r.json.repeat === true, 'r5 the very same copy again: ok (repeat)', r);
r = await read('/backup/meta');
check(r.json.accepted.length === 3, 'r5 the record is unchanged by the repeat');

// r6 — a record sent by a phone inside its copy is dropped: only the registry writes it
const forged = copy(7316, 5, { accepted: [{ v: 999999, fp: 'ff'.repeat(32), at: 1 }], fingerprint: 'ee'.repeat(32) });
r = await push(forged);
check(r.status === 200, 'r6 a copy carrying its own "accepted" list and "fingerprint" is stored', r);
r = await read('/backup/meta');
check(!r.json.accepted.some((e) => e.v === 999999) && r.json.accepted[r.json.accepted.length - 1].v === 7316 && r.json.fingerprint === fpOf(forged), 'r6 the phone\'s list and fingerprint are dropped: the record and the fingerprint are the registry\'s', r.json);

// r7 — the record keeps the last 8
for (let v = 7317; v <= 7326; v++) { r = await push(copy(v, v % 200)); if (r.status !== 200) check(false, 'r7 push ' + v, r); }
r = await read('/backup/meta');
check(r.json.accepted.length === 8 && r.json.accepted[0].v === 7319 && r.json.accepted[7].v === 7326, 'r7 the record keeps the last 8 accepted uploads (7319 … 7326)', r.json.accepted.map((e) => e.v));

// r8 — a copy stored before 0.10.0 (no fingerprint): the refusal names no fingerprint
const priv2 = randomBytes(32), pub2 = hex(secp.getPublicKey(priv2, true));
store.set('backup:' + pub2, JSON.stringify({ pubkey_hex: pub2, version: 50, saved_at_ms: 9, encrypted_data: bytes(1, 8) }));
{ const nonce = (await call('GET', '/backup/challenge?pubkey=' + pub2)).json.nonce; const blob = { pubkey_hex: pub2, version: 50, saved_at_ms: 10, encrypted_data: bytes(2, 8) };
  r = await call('POST', '/backup', { pubkey_hex: pub2, nonce, signature: hex(secp.sign(digestV2('backup-push', nonce, pub2, fpOf(blob), 50), priv2).toCompactRawBytes()), auth_v: 2, blob }); }
check(r.status === 409 && r.json.existing_version === 50 && r.json.existing_fingerprint === null && r.json.existing_saved_at_ms === 9, 'r8 a held copy without a fingerprint: the refusal says existing_fingerprint null', r);

// r9 — the copy itself is read back whole
r = await read('/backup/fetch');
const got = r.json && (r.json.blob || r.json);
check(r.status === 200 && got && got.version === 7326 && Array.isArray(got.encrypted_data) && got.encrypted_data.length === 64, 'r9 /backup/fetch still returns the copy whole', r.status);

console.log(fails ? ('GATE FAIL · test-round9 · ' + fails) : 'GATE PASS · test-round9 (r1–r9): a refusal names the copy held; the registry\'s record of accepted uploads');
process.exit(fails ? 1 : 0);
