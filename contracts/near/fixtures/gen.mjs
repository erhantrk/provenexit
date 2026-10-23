#!/usr/bin/env node
// Cross-implementation test vectors for the Rust registry (contracts/near/src/tests.rs).
//
// Every quote/event log here is produced with the TypeScript reference library (@plr/shared, built to
// packages/shared/dist). For every registration case the expected registry error code is computed by
// `tsRegistryVerify`, a direct transcription of SPEC §7 steps 1-7 on top of the TS verifiers, and must equal the
// code the case was designed to hit — so the Rust contract is checked against the TS implementation, not against
// hand-written expectations.
//
// Usage (from the repo root):  npx tsc -b packages/shared && node contracts/near/fixtures/gen.mjs
import { writeFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { p256 } from "@noble/curves/nist.js";
import { ed25519, x25519 } from "@noble/curves/ed25519.js";
import { sha256 } from "@noble/hashes/sha2.js";
import {
  MockRoot, MockTdxAttester, MockVerifier, PlrError, MOCK_QE_VENDOR_ID, MOCK_AK_CERT_PREFIX, QUOTE,
  anchorMessage, bootEvents, concatBytes, encodeQuote, fromHex, isDebug, keyHash, makeEvent, mockOsReport,
  osMeasurement, parseJsonIntegers, parseQuote, registrationNonce, replayRtmr3, reportData, toHex, utf8, verifyEventLog,
} from "../../../packages/shared/dist/index.js";

const here = dirname(fileURLToPath(import.meta.url));
const CONTRACT_ID = "registry.test.near";
const seed = (label) => sha256(utf8(`plr-registry-fixture:${label}`));

// ---------- deterministic actors ----------
const root = MockRoot.fromSecret(seed("root"));
const otherRoot = MockRoot.fromSecret(seed("other-root"));
const akSk = seed("ak");
const akPub = p256.getPublicKey(akSk, false).slice(1);
const N = p256.Point.CURVE().n;

function keysFrom(label) {
  const xs = seed(`${label}:x`), es = seed(`${label}:e`);
  return { xs, xp: x25519.getPublicKey(xs), es, ep: ed25519.getPublicKey(es) };
}
const K = keysFrom("router");
const K2 = keysFrom("router-2");

const canon = (o) => (Array.isArray(o) ? o.map(canon) : o && typeof o === "object"
  ? Object.fromEntries(Object.keys(o).sort().map((k) => [k, canon(o[k])])) : o);
const composeDoc = (bundle) => JSON.stringify(canon({
  llm: { kind: "mock", model_sha256: "11".repeat(32), runtime: "mock-llm" },
  manifest_version: 1,
  name: "plr-router",
  policy: { disk: "none", egress: [], logs: "none" },
  router: { bundle_sha256: bundle, entry: "router.bundle.mjs" },
}), null, 2) + "\n";
const COMPOSE = composeDoc("aa".repeat(32));
const EVIL_COMPOSE = composeDoc("ee".repeat(32));
const composeBytes = utf8(COMPOSE);
const COMPOSE_HASH = sha256(composeBytes);
const OS = osMeasurement(mockOsReport());
const INSTANCE_ID = seed("instance").slice(0, 20);
const regNonce = registrationNonce(CONTRACT_ID);

// ---------- TS transcription of SPEC §7 register_instance ----------
const policy = { compose: new Set([toHex(COMPOSE_HASH)]), os: new Set([toHex(OS)]) };
function tsRegistryVerify(a) {
  const code = (e) => {
    if (!(e instanceof PlrError)) throw e;
    return e.code === "E_TEE_TYPE" || e.code === "E_BAD_HEX" ? "E_QUOTE_FORMAT" : e.code;
  };
  let parsed;
  try {
    if (a.quote.length > 4096) return "E_QUOTE_FORMAT";
    parsed = new MockVerifier(root.publicKey).verify(fromHex(a.quote)); // steps 1 + 2
  } catch (e) { return code(e); }
  if (isDebug(parsed.report)) return "E_DEBUG_TD"; // 3
  let boot;
  try { boot = verifyEventLog(a.event_log, parsed.report.rtmr[3]); } catch (e) { return code(e); } // 4
  if (toHex(sha256(utf8(a.app_compose))) !== toHex(boot.composeHash)) return "E_COMPOSE_MISMATCH"; // 5
  if (!policy.compose.has(toHex(boot.composeHash))) return "E_COMPOSE_NOT_ALLOWED"; // 6
  if (!policy.os.has(toHex(osMeasurement(parsed.report)))) return "E_OS_NOT_ALLOWED";
  const want = reportData(fromHex(a.x25519, 32), fromHex(a.ed25519, 32), regNonce); // 7
  if (toHex(parsed.report.reportData) !== toHex(want)) return "E_REPORT_DATA";
  return "ok";
}

// ---------- quote crafting (known AK so event logs / measurements can be chosen freely) ----------
const signLowS = (msg, sk) => p256.sign(msg, sk, { prehash: true, lowS: true, format: "compact" });
function highS(sig) {
  const s = BigInt("0x" + toHex(sig.slice(32)));
  const out = sig.slice();
  out.set(fromHex((N - s).toString(16).padStart(64, "0"), 32), 32);
  return out;
}
function craft({ events, rd, debug = false, rtmr3, report: patch, sigData }) {
  const report = mockOsReport({ debug });
  report.rtmr[3] = rtmr3 ?? replayRtmr3(events);
  report.reportData = rd;
  if (patch) patch(report);
  const header = { qeVendorId: MOCK_QE_VENDOR_ID };
  const unsigned = encodeQuote(header, report, new Uint8Array(QUOTE.MOCK_SIG_DATA_LEN));
  const qsig = signLowS(unsigned.subarray(0, QUOTE.SIGNED_LEN), akSk);
  const cert = root.certifyAk(akPub);
  return encodeQuote(header, report, sigData ? sigData({ qsig, akPub, cert, unsigned }) : concatBytes(qsig, akPub, cert));
}

const boot = bootEvents(composeBytes, INSTANCE_ID);
const rdOk = reportData(K.xp, K.ep, regNonce);
const base = (quote, events = boot, extra = {}) => ({
  quote: toHex(quote), event_log: events, app_compose: COMPOSE, x25519: toHex(K.xp), ed25519: toHex(K.ep), ...extra,
});
const withEvents = (events, extra) => base(craft({ events, rd: rdOk }), events, extra);
/** Quote measured for the honest boot log, but submitted with `events` (malformed logs that cannot be replayed). */
const withRawEvents = (events) => base(craft({ events: boot, rd: rdOk }), events);
const ev = (name, payload) => makeEvent(name, payload);
const patchHex = (hex, byteOff, bytes) => hex.slice(0, byteOff * 2) + toHex(bytes) + hex.slice((byteOff + bytes.length) * 2);

const cases = [];
const add = (name, expect, args) => cases.push({ name, expect, ...args });

// --- accepted ---
const attester = new MockTdxAttester({ root, composeBytes, instanceId: INSTANCE_ID });
const honest = await attester.getQuote(rdOk);
const okArgs = base(honest.quote, honest.eventLog);
add("ok_mock_tdx_attester", "ok", okArgs);
add("ok_extra_events_after_boot", "ok", withEvents([...boot, ev("app-ready", Uint8Array.of(1)), ev("max-payload", new Uint8Array(256).fill(7))]));
add("ok_64_events", "ok", withEvents([...boot, ...Array.from({ length: 59 }, (_, i) => ev(`e${i}`, new Uint8Array(0)))]));
{
  const a2 = new MockTdxAttester({ root, composeBytes });
  const q2 = await a2.getQuote(reportData(K2.xp, K2.ep, regNonce));
  add("ok_second_instance", "ok", base(q2.quote, q2.eventLog, { x25519: toHex(K2.xp), ed25519: toHex(K2.ep) }));
}

// --- step 1: E_QUOTE_FORMAT ---
const okQ = okArgs.quote;
add("format_truncated", "E_QUOTE_FORMAT", { ...okArgs, quote: okQ.slice(0, 1200) });
add("format_empty", "E_QUOTE_FORMAT", { ...okArgs, quote: "" });
add("format_trailing_byte", "E_QUOTE_FORMAT", { ...okArgs, quote: okQ + "00" });
add("format_uppercase_hex", "E_QUOTE_FORMAT", { ...okArgs, quote: okQ.toUpperCase() });
add("format_odd_hex", "E_QUOTE_FORMAT", { ...okArgs, quote: okQ.slice(0, -1) });
add("format_too_large", "E_QUOTE_FORMAT", { ...okArgs, quote: okQ + "00".repeat(1300) });
add("format_version_5", "E_QUOTE_FORMAT", { ...okArgs, quote: patchHex(okQ, 0, Uint8Array.of(5, 0)) });
add("format_att_key_type_3", "E_QUOTE_FORMAT", { ...okArgs, quote: patchHex(okQ, 2, Uint8Array.of(3, 0)) });
add("format_tee_type_sgx", "E_QUOTE_FORMAT", { ...okArgs, quote: patchHex(okQ, 4, Uint8Array.of(0, 0, 0, 0)) });
add("format_reserved_nonzero", "E_QUOTE_FORMAT", { ...okArgs, quote: patchHex(okQ, 8, Uint8Array.of(0, 0, 1, 0)) });
add("format_intel_vendor", "E_QUOTE_FORMAT", { ...okArgs, quote: patchHex(okQ, 12, fromHex("939a7233f79c4ca9940a0db3957f0607")) });
add("format_sig_len_191", "E_QUOTE_FORMAT", { ...okArgs, quote: patchHex(okQ, 632, Uint8Array.of(191, 0, 0, 0)) });

// --- step 2: E_QUOTE_SIG ---
add("sig_body_bitflip", "E_QUOTE_SIG", { ...okArgs, quote: patchHex(okQ, 300, Uint8Array.of(fromHex(okQ.slice(600, 602))[0] ^ 1)) });
{
  const wrongRoot = await new MockTdxAttester({ root: otherRoot, composeBytes, instanceId: INSTANCE_ID }).getQuote(rdOk);
  add("sig_wrong_root", "E_QUOTE_SIG", base(wrongRoot.quote, wrongRoot.eventLog));
}
{
  const q = craft({ events: boot, rd: rdOk, sigData: ({ qsig, akPub, cert }) => concatBytes(highS(qsig), akPub, cert) });
  const hs = q.slice(636, 700);
  if (!p256.verify(hs, q.subarray(0, 632), concatBytes(Uint8Array.of(4), akPub), { prehash: true, lowS: false, format: "compact" })) {
    throw new Error("high-S quote_sig must be otherwise valid");
  }
  add("sig_high_s_quote_sig", "E_QUOTE_SIG", base(q));
}
{
  const q = craft({ events: boot, rd: rdOk, sigData: ({ qsig, akPub, cert }) => concatBytes(qsig, akPub, highS(cert)) });
  const hs = q.slice(764, 828);
  if (!p256.verify(hs, concatBytes(MOCK_AK_CERT_PREFIX, akPub), concatBytes(Uint8Array.of(4), root.publicKey), { prehash: true, lowS: false, format: "compact" })) {
    throw new Error("high-S ak_cert_sig must be otherwise valid");
  }
  add("sig_high_s_ak_cert", "E_QUOTE_SIG", base(q));
}
{
  // Root certifies AK bytes that are not a curve point (same x, y+2: same parity, so naive compression would
  // silently "fix" it). The quote signature is by the real AK.
  const offCurve = akPub.slice();
  offCurve[63] ^= 0x02;
  const q = craft({
    events: boot, rd: rdOk,
    sigData: ({ qsig }) => concatBytes(qsig, offCurve, signLowS(concatBytes(MOCK_AK_CERT_PREFIX, offCurve), root.secretKey)),
  });
  add("sig_ak_off_curve", "E_QUOTE_SIG", base(q));
}
{
  // AK certificate signed by the root but over a different prefix.
  const q = craft({ events: boot, rd: rdOk, sigData: ({ qsig, akPub }) => concatBytes(qsig, akPub, signLowS(concatBytes(utf8("PLR-MOCK-AK-v2"), akPub), root.secretKey)) });
  add("sig_ak_cert_wrong_prefix", "E_QUOTE_SIG", base(q));
}
add("sig_zero_signatures", "E_QUOTE_SIG", { ...okArgs, quote: patchHex(okQ, 636, new Uint8Array(64)) });

// --- step 3: E_DEBUG_TD ---
{
  const dbg = await new MockTdxAttester({ root, composeBytes, instanceId: INSTANCE_ID, debug: true }).getQuote(rdOk);
  add("debug_td", "E_DEBUG_TD", base(dbg.quote, dbg.eventLog));
}

// --- step 4: E_EVENT_LOG / E_RTMR3 ---
const swap = (a, i, j) => { const b = [...a]; [b[i], b[j]] = [b[j], b[i]]; return b; };
add("log_reserved_name_reused", "E_EVENT_LOG", withEvents([...boot, ev("compose-hash", COMPOSE_HASH)]));
add("log_order_swapped", "E_EVENT_LOG", withEvents(swap(boot, 0, 1)));
add("log_missing_boot_done", "E_EVENT_LOG", withEvents(boot.slice(0, 4)));
add("log_event_before_boot_done", "E_EVENT_LOG", withEvents([...boot.slice(0, 4), ev("early", Uint8Array.of(1)), boot[4]]));
add("log_app_id_mismatch", "E_EVENT_LOG", withEvents([boot[0], ev("app-id", new Uint8Array(20).fill(9)), ...boot.slice(2)]));
add("log_compose_hash_31_bytes", "E_EVENT_LOG", withEvents([boot[0], ev("app-id", COMPOSE_HASH.slice(0, 20)), ev("compose-hash", COMPOSE_HASH.slice(0, 31)), ...boot.slice(3)]));
add("log_instance_id_21_bytes", "E_EVENT_LOG", withEvents([...boot.slice(0, 3), ev("instance-id", new Uint8Array(21)), boot[4]]));
add("log_system_preparing_payload", "E_EVENT_LOG", withEvents([ev("system-preparing", Uint8Array.of(0)), ...boot.slice(1)]));
add("log_boot_done_payload", "E_EVENT_LOG", withEvents([...boot.slice(0, 4), ev("boot-mr-done", Uint8Array.of(0))]));
add("log_payload_257_bytes", "E_EVENT_LOG", withEvents([...boot, ev("big", new Uint8Array(257))]));
add("log_65_events", "E_EVENT_LOG", withEvents([...boot, ...Array.from({ length: 60 }, (_, i) => ev(`e${i}`, new Uint8Array(0)))]));
add("log_name_with_colon", "E_EVENT_LOG", withEvents([...boot, ev("a:b", new Uint8Array(0))]));
add("log_name_with_space", "E_EVENT_LOG", withEvents([...boot, ev("a b", new Uint8Array(0))]));
add("log_name_empty", "E_EVENT_LOG", withEvents([...boot, ev("", new Uint8Array(0))]));
add("log_name_129_chars", "E_EVENT_LOG", withEvents([...boot, ev("n".repeat(129), new Uint8Array(0))]));
add("log_name_non_ascii", "E_EVENT_LOG", withEvents([...boot, ev("café", new Uint8Array(0))]));
add("log_imr_2", "E_EVENT_LOG", withEvents([...boot.slice(0, 4), { ...boot[4], imr: 2 }]));
add("log_event_type_wrong", "E_EVENT_LOG", withEvents([...boot.slice(0, 4), { ...boot[4], event_type: 1 }]));
add("log_unknown_field", "E_EVENT_LOG", withEvents([...boot.slice(0, 4), { ...boot[4], extra: 1 }]));
add("log_missing_field", "E_EVENT_LOG", withRawEvents([...boot.slice(0, 4), (({ digest, ...r }) => r)(boot[4])]));
add("log_digest_uppercase", "E_EVENT_LOG", withRawEvents([...boot.slice(0, 4), { ...boot[4], digest: boot[4].digest.toUpperCase() }]));
add("log_payload_uppercase", "E_EVENT_LOG", withEvents([...boot.slice(0, 3), { ...boot[3], event_payload: boot[3].event_payload.toUpperCase() }]));
add("log_event_not_object", "E_EVENT_LOG", withRawEvents([...boot, "boot-mr-done"]));
add("log_not_array", "E_EVENT_LOG", { ...okArgs, event_log: { events: boot } });
{
  // Tampered instance-id payload with the original digest (the locked e2e case): digest recomputation fails.
  const t = [...okArgs.event_log];
  t[3] = { ...t[3], event_payload: "00".repeat(20) };
  add("log_payload_tampered", "E_EVENT_LOG", { ...okArgs, event_log: t });
  add("log_truncated_to_4", "E_EVENT_LOG", { ...okArgs, event_log: okArgs.event_log.slice(0, 4) });
}
{
  // Well-formed log of a different boot (other instance id): replays fine but not to this quote's RTMR3.
  const otherBoot = bootEvents(composeBytes, new Uint8Array(20).fill(5));
  add("rtmr3_mismatch", "E_RTMR3", { ...okArgs, event_log: otherBoot });
  add("rtmr3_extra_event_not_quoted", "E_RTMR3", { ...okArgs, event_log: [...okArgs.event_log, ev("later", Uint8Array.of(1))] });
}

// --- step 5: E_COMPOSE_MISMATCH ---
add("compose_mismatch", "E_COMPOSE_MISMATCH", { ...okArgs, app_compose: COMPOSE.replace("plr-router", "plr-routex") });
add("compose_reserialised", "E_COMPOSE_MISMATCH", { ...okArgs, app_compose: JSON.stringify(JSON.parse(COMPOSE)) });
add("compose_trailing_newline_dropped", "E_COMPOSE_MISMATCH", { ...okArgs, app_compose: COMPOSE.trimEnd() });

// --- step 6: allowlists ---
{
  const evilBytes = utf8(EVIL_COMPOSE);
  const evil = await new MockTdxAttester({ root, composeBytes: evilBytes, instanceId: INSTANCE_ID }).getQuote(rdOk);
  add("compose_not_allowed", "E_COMPOSE_NOT_ALLOWED", base(evil.quote, evil.eventLog, { app_compose: EVIL_COMPOSE }));
  const q = craft({ events: boot, rd: rdOk, report: (r) => { r.mrTd = new Uint8Array(48).fill(1); } });
  add("os_not_allowed", "E_OS_NOT_ALLOWED", base(q));
  const q2 = craft({ events: boot, rd: rdOk, report: (r) => { r.rtmr[2] = new Uint8Array(48).fill(2); } });
  add("os_not_allowed_rtmr2", "E_OS_NOT_ALLOWED", base(q2));
}

// --- step 7: E_REPORT_DATA ---
add("report_data_session_nonce", "E_REPORT_DATA", base(craft({ events: boot, rd: reportData(K.xp, K.ep, seed("session-nonce")) })));
add("report_data_other_registry", "E_REPORT_DATA", base(craft({ events: boot, rd: reportData(K.xp, K.ep, registrationNonce("other.test.near")) })));
add("report_data_claimed_x25519_differs", "E_REPORT_DATA", { ...okArgs, x25519: toHex(K2.xp) });
add("report_data_claimed_ed25519_differs", "E_REPORT_DATA", { ...okArgs, ed25519: toHex(K2.ep) });
add("report_data_keys_swapped", "E_REPORT_DATA", { ...okArgs, x25519: toHex(K.ep), ed25519: toHex(K.xp) });
add("report_data_halves_swapped", "E_REPORT_DATA", base(craft({ events: boot, rd: concatBytes(regNonce, keyHash(K.xp, K.ep)) })));

// The TS transcription must agree with every designed expectation.
for (const c of cases) {
  const got = tsRegistryVerify(c);
  if (got !== c.expect) throw new Error(`fixture ${c.name}: TS says ${got}, designed ${c.expect}`);
}

// ---------- anchor scenario (on the ok_mock_tdx_attester instance, in order) ----------
const KH = keyHash(K.xp, K.ep);
const rootOf = (label) => seed(`merkle:${label}`);
const anchorStep = (name, expect, firstSeq, count, o = {}) => {
  const kh = o.kh ?? KH, r = o.root ?? rootOf(name);
  const msg = anchorMessage({ contractId: o.contractId ?? CONTRACT_ID, keyHash: kh, root: r, firstSeq: BigInt(firstSeq), count: BigInt(count) });
  return { name, expect, key_hash: toHex(kh), root: toHex(r), first_seq: firstSeq, count, sig: toHex(ed25519.sign(msg, o.sk ?? K.es)), msg: toHex(msg) };
};
const anchors = [
  anchorStep("first_batch", "ok", 0, 3),
  anchorStep("rewind", "E_SEQ", 0, 1),
  anchorStep("gap", "E_SEQ", 10, 1),
  anchorStep("count_zero", "E_SEQ", 3, 0),
  anchorStep("count_too_big", "E_SEQ", 3, 10_001),
  anchorStep("other_key", "E_ANCHOR_SIG", 3, 1, { sk: K2.es }),
  anchorStep("other_contract", "E_ANCHOR_SIG", 3, 1, { contractId: "other.test.near" }),
  anchorStep("unknown_instance", "E_INSTANCE_NOT_REGISTERED", 0, 1, { kh: seed("unknown-kh") }),
  anchorStep("second_batch", "ok", 3, 10_000),
  anchorStep("third_batch", "ok", 10_003, 1),
];

// ---------- JSON number literals in event logs (TS and Rust must agree) ----------
// `event_log_json` is raw JSON TEXT: `3.0`, `3e0`, `0.3e1` are the integer 3 to a lenient parser but are not
// integer literals. serde_json (`as_u64`) rejects them, so the TS side (parseJsonIntegers + verifyEventLog)
// must reject them too, with E_EVENT_LOG. The expectation is computed with the TS library and must equal the
// designed one; tests.rs replays the same text through `register_instance`.
const okLogJson = JSON.stringify(okArgs.event_log);
const literalCase = (name, expect, from, to) => {
  if (!okLogJson.includes(from)) throw new Error(`number_literals ${name}: pattern not found`);
  const text = okLogJson.replace(from, to); // first event only
  let got = "ok";
  try {
    verifyEventLog(parseJsonIntegers(text), parseQuote(fromHex(okArgs.quote)).report.rtmr[3]);
  } catch (e) {
    got = e instanceof PlrError ? e.code : "throw";
  }
  if (got !== expect) throw new Error(`number_literals ${name}: TS says ${got}, designed ${expect}`);
  return { name, expect, event_log_json: text };
};
const numberLiterals = [
  literalCase("imr_integer", "ok", '"imr":3,', '"imr":3,'),
  literalCase("imr_fraction", "E_EVENT_LOG", '"imr":3,', '"imr":3.0,'),
  literalCase("imr_exponent", "E_EVENT_LOG", '"imr":3,', '"imr":3e0,'),
  literalCase("imr_fraction_exponent", "E_EVENT_LOG", '"imr":3,', '"imr":0.3e1,'),
  literalCase("imr_upper_exponent", "E_EVENT_LOG", '"imr":3,', '"imr":3E0,'),
  literalCase("event_type_fraction", "E_EVENT_LOG", '"event_type":134217729,', '"event_type":134217729.0,'),
  literalCase("event_type_exponent", "E_EVENT_LOG", '"event_type":134217729,', '"event_type":1.34217729e8,'),
];

// ---------- primitive vectors ----------
const vectors = {
  key_hash: [{ x25519: toHex(K.xp), ed25519: toHex(K.ep), key_hash: toHex(KH) }, { x25519: toHex(K2.xp), ed25519: toHex(K2.ep), key_hash: toHex(keyHash(K2.xp, K2.ep)) }],
  registration_nonce: ["registry.test.near", "plr.test.near", "a"].map((id) => ({ contract_id: id, nonce: toHex(registrationNonce(id)) })),
  event_digests: [...boot, ev("app-ready", Uint8Array.of(1, 2, 3))].map((e) => ({ event: e.event, event_payload: e.event_payload, digest: e.digest })),
  rtmr3: { events: boot, rtmr3: toHex(replayRtmr3(boot)) },
  ak_pub: toHex(akPub),
  ak_cert: toHex(root.certifyAk(akPub)),
};

const out = {
  generated_by: "contracts/near/fixtures/gen.mjs (@plr/shared dist)",
  contract_id: CONTRACT_ID,
  root_p256: toHex(root.publicKey),
  other_root_p256: toHex(otherRoot.publicKey),
  compose_hash: toHex(COMPOSE_HASH),
  os_measurement: toHex(OS),
  key_hash: toHex(KH),
  registrations: cases,
  number_literals: numberLiterals,
  anchors,
  vectors,
};
writeFileSync(join(here, "vectors.json"), JSON.stringify(out, null, 1) + "\n");
console.log(`wrote ${cases.length} registration cases, ${anchors.length} anchor steps`);
