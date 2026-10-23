// LOCKED — SPEC §3
import { describe, it, expect } from "vitest";
import { EVENT_TYPE, makeEvent, replayRtmr3, verifyEventLog, bootEvents, PlrError, type TdxEvent } from "../src/index.js";
import { sha256, enc, hex, unhex, refEventDigest, refReplay, COMPOSE_STR } from "./helpers.js";

const code = (fn: () => unknown) => { try { fn(); } catch (e) { expect(e).toBeInstanceOf(PlrError); return (e as PlrError).code; } return "NO_THROW"; };
const compose = enc(COMPOSE_STR);
const iid = new Uint8Array(20).fill(0xab);
const boot = () => bootEvents(compose, iid);
const rt = (evs: TdxEvent[]) => refReplay(evs.map((e) => unhex(e.digest)));

describe("makeEvent", () => {
  it("computes the dstack digest", () => {
    const e = makeEvent("compose-hash", new Uint8Array([1, 2, 3]));
    expect(EVENT_TYPE).toBe(0x08000001);
    expect(e).toEqual({
      imr: 3, event_type: 0x08000001, event: "compose-hash", event_payload: "010203",
      digest: hex(refEventDigest("compose-hash", new Uint8Array([1, 2, 3]))),
    });
    expect(makeEvent("boot-mr-done", new Uint8Array()).digest).toBe(hex(refEventDigest("boot-mr-done", new Uint8Array())));
  });
});

describe("bootEvents", () => {
  it("emits the exact required sequence", () => {
    const evs = boot();
    expect(evs.map((e) => e.event)).toEqual(["system-preparing", "app-id", "compose-hash", "instance-id", "boot-mr-done"]);
    expect(evs[0]!.event_payload).toBe("");
    expect(evs[1]!.event_payload).toBe(hex(sha256(compose).slice(0, 20)));
    expect(evs[2]!.event_payload).toBe(hex(sha256(compose)));
    expect(evs[3]!.event_payload).toBe(hex(iid));
    expect(evs[4]!.event_payload).toBe("");
  });
});

describe("replayRtmr3", () => {
  it("matches the reference replay", () => {
    expect(hex(replayRtmr3(boot()))).toBe(hex(rt(boot())));
    expect(replayRtmr3([])).toEqual(new Uint8Array(48));
  });
});

describe("verifyEventLog", () => {
  it("accepts a valid boot log and extracts ids", () => {
    const evs = boot();
    const out = verifyEventLog(evs, rt(evs));
    expect(hex(out.composeHash)).toBe(hex(sha256(compose)));
    expect(hex(out.appId)).toBe(hex(sha256(compose).slice(0, 20)));
    expect(out.instanceId).toEqual(iid);
  });

  it("accepts non-reserved runtime events after boot-mr-done", () => {
    const evs = [...boot(), makeEvent("app-ready", enc("ok"))];
    expect(() => verifyEventLog(evs, rt(evs))).not.toThrow();
  });

  it("rejects RTMR3 mismatch", () => {
    const evs = boot();
    expect(code(() => verifyEventLog(evs, new Uint8Array(48)))).toBe("E_RTMR3");
  });

  const bad: Array<[string, (e: TdxEvent[]) => TdxEvent[]]> = [
    ["digest does not match payload", (e) => { e[2] = { ...e[2]!, event_payload: "00".repeat(32) }; return e; }],
    ["wrong imr", (e) => { e[1] = { ...e[1]!, imr: 2 }; return e; }],
    ["wrong event_type", (e) => { e[1] = { ...e[1]!, event_type: 1 }; return e; }],
    ["missing compose-hash", (e) => e.filter((x) => x.event !== "compose-hash")],
    ["out of order", (e) => [e[0]!, e[2]!, e[1]!, e[3]!, e[4]!]],
    ["duplicate compose-hash after boot", (e) => [...e, makeEvent("compose-hash", new Uint8Array(32))]],
    ["reserved name after boot", (e) => [...e, makeEvent("instance-id", new Uint8Array(20))]],
    ["event before system-preparing", (e) => [makeEvent("x", new Uint8Array()), ...e]],
    ["compose-hash payload wrong length", (e) => { e[2] = makeEvent("compose-hash", new Uint8Array(31)); return e; }],
    ["app-id not derived from compose-hash", (e) => { e[1] = makeEvent("app-id", new Uint8Array(20)); return e; }],
    ["instance-id wrong length", (e) => { e[3] = makeEvent("instance-id", new Uint8Array(8)); return e; }],
    ["non-empty system-preparing", (e) => { e[0] = makeEvent("system-preparing", new Uint8Array(1)); return e; }],
    ["uppercase hex", (e) => { e[3] = { ...e[3]!, event_payload: e[3]!.event_payload.toUpperCase() }; return e; }],
    ["oversized payload", (e) => [...e, makeEvent("big", new Uint8Array(257))]],
    ["too many events", (e) => [...e, ...Array.from({ length: 60 }, (_, i) => makeEvent(`e${i}`, new Uint8Array()))]],
  ];
  for (const [name, f] of bad) {
    it(`rejects: ${name}`, () => {
      const evs = f(boot());
      // RTMR3 is computed over the (possibly tampered) provided digests, so only the log check can catch it.
      expect(code(() => verifyEventLog(evs, rt(evs)))).toBe("E_EVENT_LOG");
    });
  }
});
