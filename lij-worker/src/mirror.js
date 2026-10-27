// lij-worker 0.17.0 (S63, Phase C — docs/design/routes/phase-c-r1.md; DP 21:41 "keep the worker as the Cloudflare
// door … the box has the same rules as the worker so they behave the same. Go"): THE TWO DOORS OF ONE REGISTRY.
//
// The registry now has two doors to the same records: the worker on Cloudflare and the box (lij-worker/node, the
// SAME code under Node with a file store). Each door verifies and stores what it is sent, exactly as before; this
// module is the small set of rules both doors share so the two stores converge:
//
//   1. THE CLOCK. Every stored key carries the time its door wrote it (KV metadata {c: ms} on the worker; the file
//      store's sidecar on the box) — one clock per request, so the keys one request writes share it. A value with a
//      newer clock replaces an older one; equal clocks are the same write (nothing to do).
//   2. THE TOMBSTONE. A delete leaves `tomb:<key>` (7 days, with the clock) so the other door can tell "deleted
//      here" from "never arrived" — a value newer than the tombstone wins; a tombstone newer than the value deletes.
//   3. WHAT IS NOT MIRRORED. `bkpchal:` — a door's open challenges are its own (each door mints its own nonces).
//   4. THE RECORD GUARDS, beyond the clock: an `lsp:` record never rolls back to an older signed `ts` (0.14.0 K5),
//      a `backup:` copy never to a lower number — the rules each door already applies to what wallets send.
//   5. THE SIGNATURE. The box drives the mirror (it pulls the worker's listing every 20 s and pushes or pulls what
//      differs); the worker's /mirror/* routes accept the box's node-less secp256k1 key alone, named by its pubkey
//      in wrangler.toml [vars] LIJ_MIRROR_PUBKEY (born on the box, never leaves it). The message signed:
//        lij-mirror:v1:<METHOD>:<path+query>:<unix s>:<sha256 hex of the body>
//      ts within 120 s; a replay inside the window re-applies the same clock — a no-op by rule 1.
//
// Imported by src/index.js (the worker; wrangler bundles it) and by node/*.js (the box) — one text, two runtimes.

export const MIRROR_SKIP_PREFIX = 'bkpchal:';
export const TOMB_PREFIX = 'tomb:';
export const TOMB_TTL_S = 7 * 24 * 3600;
export const MIRROR_TS_WINDOW_S = 120;

export function mirrorable(key) {
  return typeof key === 'string' && key.length > 0 && !key.startsWith(MIRROR_SKIP_PREFIX);
}

// A store that stamps the clock on every put and leaves a tombstone on every delete — wraps any KV-shaped store
// (get / getWithMetadata / put / delete / list). `now` is the request's clock (one Date.now() per request).
export function clockedStore(kv, now) {
  return {
    get: (k, o) => kv.get(k, o),
    getWithMetadata: (k, o) => (typeof kv.getWithMetadata === 'function' ? kv.getWithMetadata(k, o) : kv.get(k, o).then((value) => ({ value, metadata: null }))),
    list: (o) => kv.list(o),
    put: async (k, v, o) => {
      if (!mirrorable(k)) return kv.put(k, v, o);
      return kv.put(k, v, Object.assign({}, o || {}, { metadata: { c: now } }));
    },
    delete: async (k) => {
      await kv.delete(k);
      if (mirrorable(k)) {
        try { await kv.put(TOMB_PREFIX + k, '1', { expirationTtl: TOMB_TTL_S, metadata: { c: now } }); } catch (_) {}
      }
    },
  };
}

export function clockOf(metadata) {
  const c = metadata && Number(metadata.c);
  return Number.isFinite(c) && c > 0 ? c : 0;
}

const dec = (b) => new TextDecoder().decode(b instanceof Uint8Array ? b : new Uint8Array(b));

// true when `incoming` may replace `stored` for this key (the clocks already say "newer"); the record's own rule.
export function recordAllows(key, incoming, stored) {
  if (!stored) return true;
  try {
    if (key.startsWith('lsp:')) {
      const a = JSON.parse(dec(incoming)), b = JSON.parse(dec(stored));
      if (Number.isFinite(Number(b.ts)) && Number.isFinite(Number(a.ts)) && Number(a.ts) < Number(b.ts)) return false;
    } else if (key.startsWith('backup:')) {
      const a = JSON.parse(dec(incoming)), b = JSON.parse(dec(stored));
      if (Number.isSafeInteger(b.version) && Number.isSafeInteger(a.version) && a.version < b.version) return false;
    }
  } catch (_) { return true; }
  return true;
}

export function mirrorMsg(method, pathAndQuery, ts, bodySha256Hex) {
  return 'lij-mirror:v1:' + [String(method).toUpperCase(), String(pathAndQuery), String(Number(ts) || 0), String(bodySha256Hex)].join(':');
}

export async function sha256Hex(bytes) {
  const d = new Uint8Array(await crypto.subtle.digest('SHA-256', bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes || 0)));
  let out = '';
  for (let i = 0; i < d.length; i++) out += d[i].toString(16).padStart(2, '0');
  return out;
}
