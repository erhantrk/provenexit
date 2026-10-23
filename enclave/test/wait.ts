/** Event-driven waiting for tests: wait for a condition, never for a fixed amount of time. */

/** Generous upper bound for every wait (only reached if the awaited event never happens). */
export const WAIT_MS = 15_000;

/**
 * Waits until `pred()` holds (re-checked at least every 10 ms), or `ms` elapsed. Returns whether it holds.
 * The bound only matters when the event never comes; success never depends on it.
 */
export async function eventually(pred: () => boolean, ms = WAIT_MS): Promise<boolean> {
  const end = Date.now() + ms;
  while (!pred() && Date.now() < end) await new Promise((r) => setTimeout(r, 10));
  return pred();
}
