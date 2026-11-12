// Bounds for one /api/status run, kept under the function's 60 s limit in vercel.json.
export const DEADLINE_MS = 55_000;
// Shorter than the bundle's defaults, so a slow RPC or archival node cannot stack up past the deadline.
export const TIMEOUTS = { verify: 20_000, egress: 8_000, chain: 5_000, events: 12_000 };

/** The promise's result, or `{ checked_at, error }` when it has not settled within `ms`. */
export function withDeadline(promise, ms = DEADLINE_MS, now = () => new Date()) {
  let timer;
  const late = new Promise((resolve) => {
    timer = setTimeout(() => resolve({ checked_at: now().toISOString(), error: "status check timed out" }), ms);
  });
  return Promise.race([promise, late]).finally(() => clearTimeout(timer));
}
