// SPEC-TDX §1.3 — dstack RTMR3 event log (INTEL mode, V1 digests).
import { existsSync, readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import {
  DSTACK_MAX_EVENT_PAYLOAD, dstackDigestV1, verifyEventLogDstack, makeEvent, replayRtmr3, toHex, PlrError,
  type TdxEvent,
} from "../src/index.js";
import { enc, hex, unhex, sha256 } from "./helpers.js";

const code = (fn: () => unknown) => {
  try { fn(); } catch (e) { expect(e).toBeInstanceOf(PlrError); return (e as PlrError).code; }
  return "NO_THROW";
};

const EMPTY = new Uint8Array(0);
const compose = enc('{"manifest_version":2,"name":"provenexit-exit","runner":"docker-compose"}\n');
const synthetic = (): TdxEvent[] => [
  makeEvent("key-provider", enc("{}")),
  makeEvent("system-preparing", EMPTY),
  makeEvent("app-id", new Uint8Array(20).fill(0x11)),
  makeEvent("compose-hash", sha256(compose)),
  makeEvent("instance-id", new Uint8Array(20).fill(0x22)),
  makeEvent("boot-mr-done", EMPTY),
  makeEvent("system-ready", EMPTY),
];

const EVENT_LOG = new URL("../../../fixtures/phala-spike/event_log.json", import.meta.url);
const QUOTE_HEX = new URL("../../../fixtures/phala-spike/quote.hex", import.meta.url);
const APP_COMPOSE = new URL("../../../fixtures/phala-spike/app_compose.json", import.meta.url);
const haveFixture = existsSync(EVENT_LOG) && existsSync(QUOTE_HEX) && existsSync(APP_COMPOSE);

describe("dstackDigestV1 (TV-E1)", () => {
  it("matches the dstack V1 digests", () => {
    expect(toHex(dstackDigestV1("app-id", unhex("deadbeef")))).toBe(
      "67b4be4efed0893cfa2bb1d35dca209ad8348b4c97f980807bcde8b9a0f26398dd0923d6eccb5aa2096d98046da8740f",
    );
    expect(toHex(dstackDigestV1("system-preparing", EMPTY))).toBe(
      "f9974020ef507068183313d0ca808e0d1ca9b2d1ad0c61f5784e7157c362c06536f5ddacdad4451693f48fcc72fff624",
    );
  });
});

describe("verifyEventLogDstack (TV-E2 synthetic)", () => {
  it("accepts the synthetic log and returns the composer payloads", () => {
    const log = synthetic();
    const out = verifyEventLogDstack(log, replayRtmr3(log));
    expect(toHex(out.composeHash)).toBe(toHex(sha256(compose)));
    expect(toHex(out.appId)).toBe("11".repeat(20));
    expect(toHex(out.appId)).not.toBe(toHex(sha256(compose).slice(0, 20)));
    expect(toHex(out.instanceId)).toBe("22".repeat(20));
  });

  it("accepts a non-boot payload of exactly DSTACK_MAX_EVENT_PAYLOAD bytes", () => {
    const log = [...synthetic(), makeEvent("key-provider", new Uint8Array(DSTACK_MAX_EVENT_PAYLOAD).fill(7))];
    expect(() => verifyEventLogDstack(log, replayRtmr3(log))).not.toThrow();
  });
});

describe("verifyEventLogDstack negatives", () => {
  it("rejects swapped app-id / compose-hash order", () => {
    const good = synthetic();
    const log = [good[0]!, good[1]!, good[3]!, good[2]!, good[4]!, good[5]!, good[6]!];
    expect(code(() => verifyEventLogDstack(log, replayRtmr3(log)))).toBe("E_EVENT_LOG");
  });

  it("rejects a duplicated compose-hash event", () => {
    const good = synthetic();
    const log = [...good.slice(0, 4), good[3]!, ...good.slice(4)];
    expect(code(() => verifyEventLogDstack(log, replayRtmr3(log)))).toBe("E_EVENT_LOG");
  });

  it("rejects a tampered digest", () => {
    const log = synthetic();
    const d = unhex(log[3]!.digest);
    d[0] = d[0]! ^ 0x01;
    log[3] = { ...log[3]!, digest: hex(d) };
    expect(code(() => verifyEventLogDstack(log, replayRtmr3(log)))).toBe("E_EVENT_LOG");
  });

  it("rejects a wrong rtmr3", () => {
    const log = synthetic();
    const rt = replayRtmr3(log);
    rt[47] = rt[47]! ^ 0x01;
    expect(code(() => verifyEventLogDstack(log, rt))).toBe("E_RTMR3");
  });

  it("rejects a 4097-byte event payload", () => {
    const log = [...synthetic(), makeEvent("key-provider", new Uint8Array(DSTACK_MAX_EVENT_PAYLOAD + 1).fill(7))];
    expect(code(() => verifyEventLogDstack(log, replayRtmr3(log)))).toBe("E_EVENT_LOG");
  });
});

describe("verifyEventLogDstack (TV-E2 real dstack log)", () => {
  it.skipIf(!haveFixture)("verifies the spike log against the quote's RTMR3", () => {
    const log = JSON.parse(readFileSync(EVENT_LOG, "utf8")) as TdxEvent[];
    const quote = unhex(readFileSync(QUOTE_HEX, "utf8").trim());
    const out = verifyEventLogDstack(log, quote.subarray(520, 568));
    expect(toHex(out.composeHash)).toBe(toHex(sha256(new Uint8Array(readFileSync(APP_COMPOSE)))));
  });
});
