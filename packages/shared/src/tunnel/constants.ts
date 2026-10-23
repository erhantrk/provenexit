/** PLR-VPN-v1 tunnel constants (SPEC-VPN §4). */
import { utf8 } from "../bytes.js";

/** `utf8("PLR-VPN-v1")` — the VPN protocol domain separator (SPEC-VPN header). */
export const VPN_DOMAIN: Uint8Array = utf8("PLR-VPN-v1");

export const TUNNEL = Object.freeze({
  /** hello version byte */
  VERSION: 1,
  /** `u8(1) ‖ att_nonce(32) ‖ epk(32)` */
  HELLO_LEN: 65,
  /** max frame payload (DATA chunk) */
  MAX_PAYLOAD: 16384,
  /** tag(16) + type(1) */
  MIN_FRAME_LEN: 17,
  /** tag(16) + type(1) + MAX_PAYLOAD */
  MAX_FRAME_LEN: 16401,
  DIR_C2S: 1,
  DIR_S2C: 2,
} as const);

export const FRAME = Object.freeze({
  CONNECT: 1,
  CONNECT_OK: 2,
  CONNECT_ERR: 3,
  DATA: 4,
  FIN: 5,
  RECEIPT: 6,
} as const);

export type TunnelDir = typeof TUNNEL.DIR_C2S | typeof TUNNEL.DIR_S2C;
export type FrameType = (typeof FRAME)[keyof typeof FRAME];

/** Max CONNECT payload (JSON `{"host":…,"port":…}`), SPEC-VPN §4.2. */
export const MAX_CONNECT_PAYLOAD = 512;
/** Max hello / CONNECT wait (SPEC-VPN §4.3, step 1 and 2) and client receipt wait (§4.3 client). */
export const TUNNEL_STEP_TIMEOUT_MS = 10_000;
/** Idle limit with no frames in either direction (SPEC-VPN §4.3 step 5). */
export const TUNNEL_IDLE_TIMEOUT_MS = 300_000;

/**
 * Per-type payload length bounds and the direction(s) a type may travel in (SPEC-VPN §4.2 table).
 * A frame violating these is a protocol error regardless of where it appears in the stream.
 */
export const FRAME_RULES: Readonly<Record<FrameType, { readonly dirs: readonly TunnelDir[]; readonly min: number; readonly max: number }>> =
  Object.freeze({
    [FRAME.CONNECT]: { dirs: [TUNNEL.DIR_C2S], min: 1, max: MAX_CONNECT_PAYLOAD },
    [FRAME.CONNECT_OK]: { dirs: [TUNNEL.DIR_S2C], min: 0, max: 0 },
    [FRAME.CONNECT_ERR]: { dirs: [TUNNEL.DIR_S2C], min: 1, max: MAX_CONNECT_PAYLOAD },
    [FRAME.DATA]: { dirs: [TUNNEL.DIR_C2S, TUNNEL.DIR_S2C], min: 1, max: TUNNEL.MAX_PAYLOAD },
    [FRAME.FIN]: { dirs: [TUNNEL.DIR_C2S, TUNNEL.DIR_S2C], min: 0, max: 0 },
    [FRAME.RECEIPT]: { dirs: [TUNNEL.DIR_S2C], min: 1, max: TUNNEL.MAX_PAYLOAD },
  });

export function isTunnelDir(d: unknown): d is TunnelDir {
  return d === TUNNEL.DIR_C2S || d === TUNNEL.DIR_S2C;
}

/** True if `type` may carry `len` payload bytes in direction `dir`. */
export function frameAllowed(type: number, dir: TunnelDir, len: number): boolean {
  if (!Object.prototype.hasOwnProperty.call(FRAME_RULES, type)) return false;
  const r = FRAME_RULES[type as FrameType];
  return r.dirs.includes(dir) && len >= r.min && len <= r.max;
}
