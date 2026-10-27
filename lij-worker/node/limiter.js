// lij-registry (Phase C, S63) — the per-address rate limit on the box, the shape of a Workers rate-limit binding
// (`limit({key}) → {success}`), so the worker's rateLimited() runs unchanged: a fixed window of `periodS` seconds per
// key, `limit` calls allowed in it (DP 21:41: "the box has the same rules as the worker so they behave the same" —
// RL_REGISTER 60/min, RL_WRITE 300/min, per client address). In memory; a restart forgets, as Cloudflare's forgets
// across locations. The table is pruned of finished windows when it grows.
export function memLimiter(limit, periodS) {
  const windows = new Map();   // key → { start: ms, n }
  const periodMs = Math.max(1, Number(periodS) || 60) * 1000;
  const max = Math.max(1, Number(limit) || 1);
  const prune = (now) => { for (const [k, w] of windows) if (now - w.start >= periodMs) windows.delete(k); };
  return {
    limit: async ({ key }) => {
      const now = Date.now();
      let w = windows.get(key);
      if (!w || now - w.start >= periodMs) { w = { start: now, n: 0 }; windows.set(key, w); }
      w.n++;
      if (windows.size > 20000) prune(now);
      return { success: w.n <= max };
    },
    size: () => windows.size,
  };
}
