/** dstack-compatible RTMR3 event log (SPEC §3). */
import { sha256, sha384 } from "@noble/hashes/sha2.js";
import { PlrError } from "../errors.js";
import { concatBytes, equalBytes, fromHex, isBytes, isHex, isPlainObject, toHex, u32le, utf8 } from "../bytes.js";

export interface TdxEvent {
  imr: number;
  event_type: number;
  digest: string;
  event: string;
  event_payload: string;
}

export const EVENT_TYPE = 0x08000001;
export const EVENT_IMR = 3;
export const MAX_EVENTS = 64;
export const MAX_EVENT_PAYLOAD = 256;
/** Event names: 1..128 printable ASCII chars, no space and no ':' (the digest separator). */
export const EVENT_NAME_RE = /^[\x21-\x39\x3b-\x7e]{1,128}$/;

export const BOOT_SEQUENCE = ["system-preparing", "app-id", "compose-hash", "instance-id", "boot-mr-done"] as const;
const RESERVED: ReadonlySet<string> = new Set(BOOT_SEQUENCE);

const COLON = utf8(":");

function eventDigest(name: string, payload: Uint8Array): Uint8Array {
  return sha384(concatBytes(u32le(EVENT_TYPE), COLON, utf8(name), COLON, payload));
}

/** Builds an IMR3 event with its dstack digest. Does not enforce verifier limits (see {@link verifyEventLog}). */
export function makeEvent(name: string, payload: Uint8Array): TdxEvent {
  if (typeof name !== "string") throw new PlrError("E_BAD_INPUT", "event name must be a string");
  if (!isBytes(payload)) throw new PlrError("E_BAD_INPUT", "event payload must be bytes");
  return {
    imr: EVENT_IMR,
    event_type: EVENT_TYPE,
    digest: toHex(eventDigest(name, payload)),
    event: name,
    event_payload: toHex(payload),
  };
}

/**
 * Replays the provided digests: `rt = 0^48; rt = SHA384(rt ‖ digest)` per event. Does NOT recompute digests;
 * use {@link verifyEventLog} for verification.
 * @throws PlrError E_EVENT_LOG on malformed digests
 */
export function replayRtmr3(events: TdxEvent[]): Uint8Array {
  if (!Array.isArray(events)) throw new PlrError("E_EVENT_LOG", "not an array");
  let rt = new Uint8Array(48);
  for (const e of events) {
    if (!isPlainObject(e) || !isHex(e.digest, 48)) throw new PlrError("E_EVENT_LOG", "bad digest");
    rt = sha384(concatBytes(rt, fromHex(e.digest, 48)));
  }
  return rt;
}

/** The five boot events for a compose document (SPEC §3). `instanceId` must be 20 bytes. */
export function bootEvents(composeBytes: Uint8Array, instanceId: Uint8Array): TdxEvent[] {
  if (!isBytes(composeBytes)) throw new PlrError("E_BAD_INPUT", "compose must be bytes");
  if (!isBytes(instanceId) || instanceId.length !== 20) throw new PlrError("E_BAD_INPUT", "instanceId must be 20 bytes");
  const composeHash = sha256(composeBytes);
  return [
    makeEvent("system-preparing", new Uint8Array(0)),
    makeEvent("app-id", composeHash.slice(0, 20)),
    makeEvent("compose-hash", composeHash),
    makeEvent("instance-id", instanceId),
    makeEvent("boot-mr-done", new Uint8Array(0)),
  ];
}

const EVENT_KEYS: ReadonlySet<string> = new Set(["imr", "event_type", "digest", "event", "event_payload"]);

function checkedEvent(e: unknown): { name: string; payload: Uint8Array; digest: Uint8Array } {
  const bad = (why: string): never => {
    throw new PlrError("E_EVENT_LOG", why);
  };
  if (!isPlainObject(e)) return bad("event is not an object");
  for (const k of Object.keys(e)) if (!EVENT_KEYS.has(k)) bad("unknown event field");
  // Integers only (Number.isSafeInteger), like the Rust contract's `as_u64`; JSON text must be parsed with
  // `parseJsonIntegers` so that `3.0` / `3e0` literals never reach this point as the integer 3.
  if (!Number.isSafeInteger(e.imr) || e.imr !== EVENT_IMR) bad("imr");
  if (!Number.isSafeInteger(e.event_type) || e.event_type !== EVENT_TYPE) bad("event_type");
  if (typeof e.event !== "string" || !EVENT_NAME_RE.test(e.event)) bad("event name");
  if (!isHex(e.digest, 48)) bad("digest encoding");
  if (!isHex(e.event_payload) || e.event_payload.length > MAX_EVENT_PAYLOAD * 2) bad("payload encoding");
  const name = e.event as string;
  const payload = fromHex(e.event_payload as string);
  const digest = fromHex(e.digest as string, 48);
  if (!equalBytes(eventDigest(name, payload), digest)) bad("digest mismatch");
  return { name, payload, digest };
}

/**
 * Verifies an event log against a quote's RTMR3 (SPEC §3): every digest recomputed, exact boot sequence,
 * reserved names never reused, limits enforced, then replay == rtmr3.
 * @throws PlrError E_EVENT_LOG (log content), E_RTMR3 (replay mismatch)
 */
export function verifyEventLog(
  events: TdxEvent[],
  rtmr3: Uint8Array,
): { composeHash: Uint8Array; appId: Uint8Array; instanceId: Uint8Array } {
  if (!Array.isArray(events)) throw new PlrError("E_EVENT_LOG", "not an array");
  if (events.length < BOOT_SEQUENCE.length || events.length > MAX_EVENTS) throw new PlrError("E_EVENT_LOG", "event count");
  if (!isBytes(rtmr3) || rtmr3.length !== 48) throw new PlrError("E_RTMR3", "rtmr3 must be 48 bytes");

  const checked = events.map(checkedEvent);
  for (let i = 0; i < checked.length; i++) {
    const name = checked[i]!.name;
    if (i < BOOT_SEQUENCE.length) {
      if (name !== BOOT_SEQUENCE[i]) throw new PlrError("E_EVENT_LOG", "boot sequence");
    } else if (RESERVED.has(name)) {
      throw new PlrError("E_EVENT_LOG", "reserved event name reused");
    }
  }
  const [prep, appIdEv, composeEv, instanceEv, done] = checked as [
    (typeof checked)[number],
    (typeof checked)[number],
    (typeof checked)[number],
    (typeof checked)[number],
    (typeof checked)[number],
  ];
  if (prep.payload.length !== 0) throw new PlrError("E_EVENT_LOG", "system-preparing payload");
  if (composeEv.payload.length !== 32) throw new PlrError("E_EVENT_LOG", "compose-hash payload");
  if (appIdEv.payload.length !== 20 || !equalBytes(appIdEv.payload, composeEv.payload.subarray(0, 20))) {
    throw new PlrError("E_EVENT_LOG", "app-id payload");
  }
  if (instanceEv.payload.length !== 20) throw new PlrError("E_EVENT_LOG", "instance-id payload");
  if (done.payload.length !== 0) throw new PlrError("E_EVENT_LOG", "boot-mr-done payload");

  let rt = new Uint8Array(48);
  for (const c of checked) rt = sha384(concatBytes(rt, c.digest));
  if (!equalBytes(rt, rtmr3)) throw new PlrError("E_RTMR3");

  return {
    composeHash: composeEv.payload.slice(),
    appId: appIdEv.payload.slice(),
    instanceId: instanceEv.payload.slice(),
  };
}
