/** dstack RTMR3 event log, INTEL mode (SPEC-TDX §1.3). V1 digests only. */
import { sha384 } from "@noble/hashes/sha2.js";
import { PlrError } from "../errors.js";
import { concatBytes, equalBytes, fromHex, isBytes, isHex, isPlainObject, u32le, utf8 } from "../bytes.js";
import { EVENT_TYPE, EVENT_NAME_RE, type TdxEvent } from "./eventlog.js";

export const DSTACK_MAX_EVENT_PAYLOAD = 4096;
const REQUIRED = ["system-preparing", "app-id", "compose-hash", "instance-id", "boot-mr-done"] as const;
const SIZES: Record<(typeof REQUIRED)[number], number> = {
  "system-preparing": 0, "app-id": 20, "compose-hash": 32, "instance-id": 20, "boot-mr-done": 0,
};
const KEYS = new Set(["imr", "event_type", "digest", "event", "event_payload"]);
const bad = (why: string): never => { throw new PlrError("E_EVENT_LOG", why); };

export function dstackDigestV1(name: string, payload: Uint8Array): Uint8Array {
  return sha384(concatBytes(u32le(EVENT_TYPE), utf8(":"), utf8(name), utf8(":"), payload));
}

export function verifyEventLogDstack(
  events: TdxEvent[],
  rtmr3: Uint8Array,
): { composeHash: Uint8Array; appId: Uint8Array; instanceId: Uint8Array } {
  if (!Array.isArray(events) || events.length < 5 || events.length > 64) bad("event count");
  if (!isBytes(rtmr3) || rtmr3.length !== 48) throw new PlrError("E_RTMR3", "rtmr3 must be 48 bytes");
  const seen = new Map<string, { index: number; payload: Uint8Array }>();
  let rt = new Uint8Array(48);
  events.forEach((e, index) => {
    if (!isPlainObject(e)) bad("event is not an object");
    for (const k of Object.keys(e)) if (!KEYS.has(k)) bad("unknown event field");
    if (e.imr !== 3 || !Number.isSafeInteger(e.imr)) bad("imr");
    if (e.event_type !== EVENT_TYPE) bad("event_type");
    if (typeof e.event !== "string" || !EVENT_NAME_RE.test(e.event)) bad("event name");
    if (!isHex(e.digest, 48)) bad("digest encoding");
    if (typeof e.event_payload !== "string" || (e.event_payload !== "" && !isHex(e.event_payload))
      || e.event_payload.length > DSTACK_MAX_EVENT_PAYLOAD * 2) bad("payload encoding");
    const payload = e.event_payload === "" ? new Uint8Array(0) : fromHex(e.event_payload);
    const digest = fromHex(e.digest, 48);
    if (!equalBytes(dstackDigestV1(e.event, payload), digest)) bad("digest mismatch");
    if ((REQUIRED as readonly string[]).includes(e.event)) {
      if (seen.has(e.event)) bad("boot event repeated");
      seen.set(e.event, { index, payload });
    }
    rt = sha384(concatBytes(rt, digest));
  });
  let last = -1;
  for (const name of REQUIRED) {
    const s = seen.get(name);
    if (s === undefined || s.index <= last) bad("boot sequence");
    if (s!.payload.length !== SIZES[name]) bad(`${name} payload`);
    last = s!.index;
  }
  if (!equalBytes(rt, rtmr3)) throw new PlrError("E_RTMR3");
  return {
    composeHash: seen.get("compose-hash")!.payload.slice(),
    appId: seen.get("app-id")!.payload.slice(),
    instanceId: seen.get("instance-id")!.payload.slice(),
  };
}
