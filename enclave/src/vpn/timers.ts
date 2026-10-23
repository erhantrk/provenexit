/**
 * The timer source of the exit tunnels (hello / CONNECT / idle / linger deadlines). Production uses Node timers;
 * tests inject a manual clock so every timeout is driven deterministically instead of by wall-clock sleeps.
 */
export interface TimerHandle {
  /** Restarts the countdown from now with the original duration. */
  refresh(): void;
  /** Cancels the timer. Idempotent. */
  clear(): void;
}

export interface Timers {
  /** Calls `fn` once after `ms` milliseconds unless cleared. */
  set(fn: () => void, ms: number): TimerHandle;
}

export const nodeTimers: Timers = Object.freeze({
  set(fn: () => void, ms: number): TimerHandle {
    const t = setTimeout(fn, ms);
    return {
      refresh: () => void t.refresh(),
      clear: () => clearTimeout(t),
    };
  },
});
