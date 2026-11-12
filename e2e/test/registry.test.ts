// LOCKED — SPEC §7: NEAR registry contract conformance, against a real near-sandbox (the VPN registry, VPN builds).
import { describe, it, expect, beforeAll, afterAll } from "vitest";
import { x25519, ed25519 } from "@noble/curves/ed25519.js";
import { randomBytes } from "@noble/hashes/utils.js";
import { keyHash, reportData, registrationNonce, registrationReportData, anchorMessage, merkleRoot, toHex, type TdxEvent } from "@plr/shared";
import { startStack, type Stack } from "../src/harness.js";

const GAS = "300000000000000";
const DEPOSIT = "100000000000000000000000"; // 0.1 NEAR for storage
const Z = "00".repeat(32);

let S: Stack;
beforeAll(async () => { S = await startStack(); }, 240_000);
afterAll(async () => { await S?.stop(); });

const rejectsWith = async (p: Promise<unknown>, codeRe: RegExp) => {
  let err: unknown;
  try { await p; } catch (e) { err = e; }
  expect(err, "expected the contract call to fail").toBeInstanceOf(Error);
  expect(String((err as Error).message)).toMatch(codeRe);
};

function keys() {
  const xs = x25519.utils.randomSecretKey(), es = ed25519.utils.randomSecretKey();
  return { xs, xp: x25519.getPublicKey(xs), es, ep: ed25519.getPublicKey(es) };
}

/** Registration quote for `operator` (§5 rev 1.3); with `sessionNonce`, a SESSION quote instead (must never register). */
async function regArgs(variant: "honest" | "evil-logger" | "debug-td", k = keys(), sessionNonce?: Uint8Array, operator?: string) {
  const rd = sessionNonce ? reportData(k.xp, k.ep, sessionNonce) : registrationReportData(k.xp, k.ep, S.vpnContractId, operator ?? S.accounts.operator);
  const a = await S.attestFor(variant === "evil-logger" ? "vpn-evil-logger" : "vpn-honest-test", rd, { debug: variant === "debug-td" });
  return {
    k,
    args: { quote: toHex(a.quote), event_log: a.eventLog as TdxEvent[], app_compose: a.appCompose, x25519: toHex(k.xp), ed25519: toHex(k.ep) },
  };
}
const register = (args: object, signer: "operator" | "stranger" = "operator") =>
  S.callVpn(signer, "register_instance", args, { deposit: DEPOSIT, gas: GAS });

describe("init & views", () => {
  it("exposes the configured MOCK root", async () => {
    expect(await S.viewVpn("get_root", {})).toEqual({ kind: "MOCK", p256: toHex(S.trustedRoot) });
    expect(await S.vpnRegistry.getRoot()).toEqual({ kind: "MOCK", p256: toHex(S.trustedRoot) });
    expect(await S.viewVpn("anchor_count", {})).toBe(0);
  });
});

describe("owner policy", () => {
  const h = "ab".repeat(32);
  it("only the owner can change the allowlist", async () => {
    await rejectsWith(S.callVpn("stranger", "allow_compose", { hash: h }), /owner|E_UNAUTHORIZED/i);
    await rejectsWith(S.callVpn("operator", "allow_os", { hash: h }), /owner|E_UNAUTHORIZED/i);
    await rejectsWith(S.callVpn("stranger", "set_root", { kind: "MOCK", p256: "11".repeat(64) }), /owner|E_UNAUTHORIZED/i);
  });
  it("rejects zero and malformed hashes", async () => {
    await rejectsWith(S.callVpn("owner", "allow_compose", { hash: Z }), /E_ZERO_HASH|zero/i);
    await rejectsWith(S.callVpn("owner", "allow_compose", { hash: "AB".repeat(32) }), /E_BAD_HEX|hex/i);
    await rejectsWith(S.callVpn("owner", "allow_compose", { hash: "ab".repeat(31) }), /E_BAD_HEX|hex|length/i);
  });
  it("allow/revoke round-trips for compose and os, visible through the reader", async () => {
    expect(await S.viewVpn("is_compose_allowed", { hash: h })).toBe(false);
    await S.callVpn("owner", "allow_compose", { hash: h });
    expect(await S.viewVpn("is_compose_allowed", { hash: h })).toBe(true);
    expect(await S.vpnRegistry.isComposeAllowed(h)).toBe(true);
    await S.callVpn("owner", "allow_os", { hash: h });
    expect(await S.viewVpn("is_allowed", { compose_hash: h, os_measurement: h })).toBe(true);
    await S.callVpn("owner", "revoke_compose", { hash: h });
    expect(await S.viewVpn("is_compose_allowed", { hash: h })).toBe(false);
    expect(await S.viewVpn("is_allowed", { compose_hash: h, os_measurement: h })).toBe(false);
    await S.callVpn("owner", "revoke_os", { hash: h });
    expect(await S.vpnRegistry.isOsAllowed(h)).toBe(false);
  });
});

describe("register_instance — on-chain quote verification", () => {
  let approved: { composeHash: string; osMeasurement: string };
  beforeAll(async () => { approved = await S.approveVpnBuild("vpn-honest-test"); }, 60_000);

  it("registers an attested instance and publishes its keys", async () => {
    const { k, args } = await regArgs("honest");
    await register(args);
    const kh = toHex(keyHash(k.xp, k.ep));
    const rec = await S.vpnRegistry.getInstance(kh);
    expect(rec).not.toBeNull();
    expect(rec).toMatchObject({
      compose_hash: approved.composeHash, os_measurement: approved.osMeasurement,
      x25519: toHex(k.xp), ed25519: toHex(k.ep), operator: S.accounts.operator, next_seq: 0,
    });
    expect(rec!.expires_at_ms).toBeGreaterThan(Date.now());
    expect(await S.viewVpn("get_instance", { key_hash: toHex(randomBytes(32)) })).toBeNull();
  });

  it("E_REPORT_DATA: session nonce instead of the registration nonce", async () => {
    const { args } = await regArgs("honest", keys(), randomBytes(32));
    await rejectsWith(register(args), /E_REPORT_DATA/);
  });

  it("E_REPORT_DATA: a session quote whose client nonce IS the registration nonce (hijack attempt, rev 1.3)", async () => {
    const { args } = await regArgs("honest", keys(), registrationNonce(S.vpnContractId, S.accounts.stranger));
    await rejectsWith(register(args, "stranger"), /E_REPORT_DATA/);
  });

  it("E_REPORT_DATA: a registration quote bound to the operator cannot be submitted by anyone else", async () => {
    const { args } = await regArgs("honest");                 // bound to accounts.operator
    await rejectsWith(register(args, "stranger"), /E_REPORT_DATA/);
    const mine = await regArgs("honest", keys(), undefined, S.accounts.stranger);
    await register(mine.args, "stranger");                     // bound to stranger, submitted by stranger: fine
    expect((await S.vpnRegistry.getInstance(toHex(keyHash(mine.k.xp, mine.k.ep))))!.operator).toBe(S.accounts.stranger);
  });

  it("E_REPORT_DATA: claimed keys differ from the quoted keys", async () => {
    const { args } = await regArgs("honest");
    await rejectsWith(register({ ...args, x25519: toHex(keys().xp) }), /E_REPORT_DATA/);
  });

  it("E_COMPOSE_NOT_ALLOWED: unapproved (evil) build", async () => {
    const { args } = await regArgs("evil-logger");
    await rejectsWith(register(args), /E_COMPOSE_NOT_ALLOWED/);
  });

  it("E_COMPOSE_MISMATCH: published compose isn't the measured one", async () => {
    const { args } = await regArgs("honest");
    await rejectsWith(register({ ...args, app_compose: args.app_compose.replace("plr-vpn", "plr-vpx") }), /E_COMPOSE_MISMATCH/);
  });

  it("E_QUOTE_SIG: any flipped bit in the signed body", async () => {
    const { args } = await regArgs("honest");
    const q = args.quote.split("");
    const i = 2 * 300; q[i] = q[i] === "0" ? "1" : "0";
    await rejectsWith(register({ ...args, quote: q.join("") }), /E_QUOTE_SIG/);
  });

  it("E_QUOTE_FORMAT: truncated quote", async () => {
    const { args } = await regArgs("honest");
    await rejectsWith(register({ ...args, quote: args.quote.slice(0, 1200) }), /E_QUOTE_FORMAT/);
  });

  it("E_DEBUG_TD: debug TD", async () => {
    const { args } = await regArgs("debug-td");
    await rejectsWith(register(args), /E_DEBUG_TD/);
  });

  it("E_EVENT_LOG / E_RTMR3: tampered event log", async () => {
    const { args } = await regArgs("honest");
    const ev = [...args.event_log];
    ev[3] = { ...ev[3]!, event_payload: "00".repeat(20) };
    await rejectsWith(register({ ...args, event_log: ev }), /E_EVENT_LOG|E_RTMR3/);
    await rejectsWith(register({ ...args, event_log: ev.slice(0, 4) }), /E_EVENT_LOG|E_RTMR3/);
  });

  it("requires a storage deposit", async () => {
    const { args } = await regArgs("honest");
    await rejectsWith(S.callVpn("operator", "register_instance", args, { gas: GAS }), /deposit|storage|E_DEPOSIT/i);
  });
});

describe("anchor_receipts", () => {
  let k: ReturnType<typeof keys>, kh: Uint8Array;
  beforeAll(async () => {
    await S.approveVpnBuild("vpn-honest-test");
    const r = await regArgs("honest");
    k = r.k; kh = keyHash(k.xp, k.ep);
    await register(r.args);
  }, 60_000);

  const anchor = (firstSeq: number, count: number, o: { sk?: Uint8Array; root?: Uint8Array; kh?: Uint8Array } = {}) => {
    const root = o.root ?? merkleRoot(Array.from({ length: count }, () => randomBytes(32)));
    const msg = anchorMessage({ contractId: S.vpnContractId, keyHash: o.kh ?? kh, root, firstSeq: BigInt(firstSeq), count: BigInt(count) });
    const sig = ed25519.sign(msg, o.sk ?? k.es);
    return S.callVpn("stranger", "anchor_receipts", {
      key_hash: toHex(o.kh ?? kh), root: toHex(root), first_seq: firstSeq, count, sig: toHex(sig),
    }, { gas: GAS });
  };

  it("accepts a batch signed by the attested key and advances next_seq", async () => {
    const before = (await S.viewVpn<number>("anchor_count", {}));
    const root = randomBytes(32);
    await anchor(0, 3, { root });
    expect(await S.viewVpn("anchor_count", {})).toBe(before + 1);
    const a = await S.vpnRegistry.getAnchor(before);
    expect(a).toMatchObject({ id: before, key_hash: toHex(kh), root: toHex(root), first_seq: 0, count: 3 });
    expect((await S.vpnRegistry.getInstance(toHex(kh)))!.next_seq).toBe(3);
  });

  it("E_SEQ: gaps or rewinds", async () => {
    await rejectsWith(anchor(0, 1), /E_SEQ/);
    await rejectsWith(anchor(10, 1), /E_SEQ/);
  });

  it("E_SEQ: count out of range", async () => {
    await rejectsWith(anchor(3, 0, { root: randomBytes(32) }), /E_SEQ/);
    await rejectsWith(anchor(3, 10_001), /E_SEQ/);
  });

  it("E_ANCHOR_SIG: signed by a non-attested key", async () => {
    await rejectsWith(anchor(3, 1, { sk: ed25519.utils.randomSecretKey() }), /E_ANCHOR_SIG/);
  });

  it("E_INSTANCE_NOT_REGISTERED: unknown key", async () => {
    await rejectsWith(anchor(0, 1, { kh: randomBytes(32) }), /E_INSTANCE_NOT_REGISTERED/);
  });

  it("E_COMPOSE_NOT_ALLOWED: after the owner revokes the build", async () => {
    const rec = (await S.vpnRegistry.getInstance(toHex(kh)))!;
    await S.callVpn("owner", "revoke_compose", { hash: rec.compose_hash });
    await rejectsWith(anchor(3, 1), /E_COMPOSE_NOT_ALLOWED/);
    await S.callVpn("owner", "allow_compose", { hash: rec.compose_hash });
    await anchor(3, 1);
  });
});

describe("operator organizations (SPEC §7 rev 1.2)", () => {
  it("only the owner can approve / revoke; org ids are validated", async () => {
    await rejectsWith(S.callVpn("stranger", "approve_operator", { account_id: S.accounts.operator, org_id: "org-a" }), /owner|E_UNAUTHORIZED/i);
    await rejectsWith(S.callVpn("operator", "approve_operator", { account_id: S.accounts.operator, org_id: "org-a" }), /owner|E_UNAUTHORIZED/i);
    await rejectsWith(S.callVpn("stranger", "revoke_operator", { account_id: S.accounts.operator }), /owner|E_UNAUTHORIZED/i);
    for (const org_id of ["", "Org-A", "-org", "org a", "o".repeat(65), "org/a"])
      await rejectsWith(S.callVpn("owner", "approve_operator", { account_id: S.accounts.operator, org_id }), /E_BAD_INPUT/);
    expect(await S.viewVpn("get_operator", { account_id: S.accounts.operator })).toBeNull();
  });

  it("get_instance carries the operator's live org_id", async () => {
    await S.approveVpnBuild("vpn-honest-test");
    const { k, args } = await regArgs("honest");
    await register(args);
    const kh = toHex(keyHash(k.xp, k.ep));
    expect((await S.vpnRegistry.getInstance(kh))!.org_id).toBeNull();
    await S.callVpn("owner", "approve_operator", { account_id: S.accounts.operator, org_id: "acme-hosting.eu" });
    expect(await S.viewVpn("get_operator", { account_id: S.accounts.operator })).toBe("acme-hosting.eu");
    expect((await S.vpnRegistry.getInstance(kh))!.org_id).toBe("acme-hosting.eu");
    expect((await S.viewVpn<{ org_id: string | null }>("get_instance", { key_hash: kh }))!.org_id).toBe("acme-hosting.eu");
    await S.callVpn("owner", "approve_operator", { account_id: S.accounts.operator, org_id: "acme-2" }); // re-approve = change
    expect((await S.vpnRegistry.getInstance(kh))!.org_id).toBe("acme-2");
    await S.callVpn("owner", "revoke_operator", { account_id: S.accounts.operator });
    expect(await S.viewVpn("get_operator", { account_id: S.accounts.operator })).toBeNull();
    expect((await S.vpnRegistry.getInstance(kh))!.org_id).toBeNull();
  });
});

describe("ownership transfer (two-step) — runs last", () => {
  it("pending owner must accept; old owner loses rights", async () => {
    await rejectsWith(S.callVpn("stranger", "accept_owner", {}), /owner|E_UNAUTHORIZED/i);
    await S.callVpn("owner", "propose_owner", { id: S.accounts.stranger });
    await S.callVpn("stranger", "accept_owner", {});
    await rejectsWith(S.callVpn("owner", "allow_compose", { hash: "cd".repeat(32) }), /owner|E_UNAUTHORIZED/i);
    await S.callVpn("stranger", "allow_compose", { hash: "cd".repeat(32) });
    expect(await S.viewVpn("is_compose_allowed", { hash: "cd".repeat(32) })).toBe(true);
  });
});
