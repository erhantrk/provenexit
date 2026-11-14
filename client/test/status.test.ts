// Status bundle against local stubs: a fake exit, a fake NEAR RPC + archival RPC, a fake NearBlocks v3.
// No real network.
import { describe, it, expect, afterEach } from "vitest";
import { readFileSync } from "node:fs";
import { createServer, type Server } from "node:http";
import type { AddressInfo } from "node:net";
import { INTEL_ROOT_P256, toHex, type RegistryReader } from "@plr/shared";
import { getStatus, type Status } from "../src/status.js";
import { startFakeExit, type FakeExit } from "./fake-exit.js";

const closers: (() => Promise<void>)[] = [];
afterEach(async () => {
  while (closers.length) await closers.pop()!();
});

const REGISTRY_ACCOUNT = "vpnregistry.test.near";
const OPERATOR = "vpn-operator.test.near";
const OWNER = "owner.test.near";
const TX_REG = "RegTx1111111111111111111111111111111111111";
const TX_ALLOW = "AllowTx11111111111111111111111111111111111";
const TX_ANCHOR = "AnchorTx1111111111111111111111111111111111";
const TX_DAO_REVOKE = "DaoRevokeTx111111111111111111111111111111";
const DAO = "owners.sputnik.test.near";
const COUNCIL = "council1.test.near";

const listen = async (server: Server): Promise<string> => {
  await new Promise<void>((ok) => server.listen(0, "127.0.0.1", ok));
  closers.push(() => new Promise<void>((ok) => { server.closeAllConnections(); server.close(() => ok()); }));
  return `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
};
const readBody = (req: import("node:http").IncomingMessage): Promise<string> =>
  new Promise((ok) => { const c: Buffer[] = []; req.on("data", (b: Buffer) => c.push(b)); req.on("end", () => ok(Buffer.concat(c).toString("utf8"))); });
const b64 = (o: unknown): string => Buffer.from(JSON.stringify(o)).toString("base64");

/** One server standing in for the NEAR RPC (views, view_account, access keys), the archival RPC (`tx`) and NearBlocks v3. */
async function startChain(reg: RegistryReader & { getInstance: RegistryReader["getInstance"] }, now: number): Promise<{ rpc: string; blocks: string; hits: string[] }> {
  const hits: string[] = [];
  const nsAt = (ms: number): string => String(BigInt(ms) * 1_000_000n);
  const server = createServer((req, res) => {
    void (async () => {
      const send = (j: unknown): void => { res.writeHead(200, { "content-type": "application/json" }); res.end(JSON.stringify(j)); };
      const url = new URL(req.url ?? "/", "http://x");
      if (url.pathname === `/v3/accounts/${DAO}/txns`) {
        hits.push("nearblocks-dao");
        // the council's transactions: a vote that executed the revoke, a vote that did not reach the registry
        return send({
          data: [
            { transaction_hash: TX_DAO_REVOKE, block_timestamp: nsAt(now - 3000), signer_account_id: COUNCIL, receiver_account_id: DAO, outcomes: { status: true }, actions: [{ action: "FUNCTION_CALL", method: "act_proposal" }] },
            { transaction_hash: "DaoVoteOnly", block_timestamp: nsAt(now - 4000), signer_account_id: COUNCIL, receiver_account_id: DAO, outcomes: { status: true }, actions: [{ action: "FUNCTION_CALL", method: "act_proposal" }] },
          ],
        });
      }
      if (url.pathname.startsWith("/v3/accounts/")) {
        hits.push("nearblocks");
        return send({
          data: [
            { transaction_hash: TX_ANCHOR, block_timestamp: nsAt(now - 1000), signer_account_id: OPERATOR, receiver_account_id: REGISTRY_ACCOUNT, outcomes: { status: true }, actions: [{ action: "FUNCTION_CALL", method: "anchor_receipts" }] },
            { transaction_hash: TX_REG, block_timestamp: nsAt(now - 5000), signer_account_id: OPERATOR, receiver_account_id: REGISTRY_ACCOUNT, outcomes: { status: true }, actions: [{ action: "FUNCTION_CALL", method: "register_instance_tdx" }] },
            { transaction_hash: "FailedTx", block_timestamp: nsAt(now - 6000), signer_account_id: OWNER, receiver_account_id: REGISTRY_ACCOUNT, outcomes: { status: false }, actions: [{ action: "FUNCTION_CALL", method: "allow_compose" }] },
            { transaction_hash: TX_ALLOW, block_timestamp: nsAt(now - 9000), signer_account_id: OWNER, receiver_account_id: REGISTRY_ACCOUNT, outcomes: { status: true }, actions: [{ action: "FUNCTION_CALL", method: "allow_compose" }] },
          ],
        });
      }
      const body = JSON.parse(await readBody(req)) as { id: string; method: string; params: Record<string, string> };
      const p = body.params;
      hits.push(`${body.method}:${p.request_type ?? ""}:${p.method_name ?? ""}`);
      const ok = (result: unknown): void => send({ jsonrpc: "2.0", id: body.id, result });
      if (body.method === "EXPERIMENTAL_tx_status") {
        const executed = p.tx_hash === TX_DAO_REVOKE;
        const fc = (method_name: string, args: unknown): unknown => ({ Action: { actions: [{ FunctionCall: { method_name, args: b64(args) } }] } });
        return ok({
          receipts: [
            { receipt_id: "R1", predecessor_id: COUNCIL, receiver_id: DAO, receipt: fc("act_proposal", { id: 2, action: "VoteApprove" }) },
            ...(executed ? [{ receipt_id: "R2", predecessor_id: DAO, receiver_id: REGISTRY_ACCOUNT, receipt: fc("revoke_compose", { hash: "ef".repeat(32) }) }] : []),
          ],
          receipts_outcome: [{ id: "R1", outcome: { status: { SuccessValue: "" } } }, { id: "R2", outcome: { status: { SuccessValue: "" } } }],
        });
      }
      if (body.method === "tx") {
        return ok({
          transaction: { actions: [{ FunctionCall: { args: b64({ hash: "ab".repeat(32) }) } }] },
          transaction_outcome: { outcome: { gas_burnt: 2_000_000_000_000 } },
          receipts_outcome: [{ outcome: { gas_burnt: 3_000_000_000_000 } }, { outcome: { gas_burnt: 1_000_000_000_000 } }],
        });
      }
      if (p.request_type === "view_account") return ok({ code_hash: "CodeHash11111111111111111111111111111111111", amount: "1" });
      if (p.request_type === "view_access_key_list") return ok({ keys: [{ public_key: "ed25519:x", access_key: { permission: { FunctionCall: {} } } }] });
      const args = JSON.parse(Buffer.from(p.args_base64 ?? "e30=", "base64").toString("utf8")) as Record<string, unknown>;
      let value: unknown;
      switch (p.method_name) {
        case "get_owner": value = DAO; break; // the owner is now a DAO; the allow_compose below was signed by the earlier owner
        case "get_root": value = await reg.getRoot(); break;
        case "is_compose_allowed": value = await reg.isComposeAllowed(args.hash as string); break;
        case "is_os_allowed": value = await reg.isOsAllowed(args.hash as string); break;
        case "get_instance": value = await reg.getInstance(args.key_hash as string); break;
        case "anchor_count": value = 1; break;
        case "get_anchor": value = { id: 0, key_hash: "11".repeat(32), root: "cd".repeat(32), first_seq: 0, count: 4, at_ms: now - 1500 }; break;
        default: return ok({ error: "MethodNotFound", logs: [] });
      }
      return ok({ result: [...Buffer.from(JSON.stringify(value), "utf8")], logs: [], block_height: 1, block_hash: "11111111111111111111111111111111" });
    })();
  });
  const base = await listen(server);
  return { rpc: base, blocks: `${base}/v3`, hits };
}

/** A destination answering the egress probe with a fixed IP. */
async function startIpEcho(ip: string): Promise<number> {
  const server = createServer((_req, res) => { res.writeHead(200, { "content-type": "text/plain", connection: "close" }); res.end(`${ip}\n`); });
  return Number(new URL(await listen(server)).port);
}

const FIXTURE = "../../fixtures/live-exit";
const rawFixture = () => {
  const rd = (n: string): string => readFileSync(new URL(`${FIXTURE}/${n}`, import.meta.url), "utf8");
  return { meta: JSON.parse(rd("meta.json")) as unknown, nonce_hex: rd("nonce.hex").trim(), bundle: JSON.parse(rd("bundle.json")) as unknown, registry: JSON.parse(rd("registry.json")) as unknown };
};

/** The status bundle's output: every field name, in every state. */
function expectBriefShape(s: Status): void {
  expect(Object.keys(s).sort()).toEqual(["checked_at", "error", "exit", "instance", "links", "receipts", "registry", "replay", "verify"]);
  expect(new Date(s.checked_at).toISOString()).toBe(s.checked_at);
  expect(Object.keys(s.exit).sort()).toEqual(["compose", "egress_ip", "online", "platform", "url"]);
  expect(Object.keys(s.verify).sort()).toEqual(["checks", "code", "root", "verdict"]);
  for (const c of s.verify.checks) expect(Object.keys(c).sort()).toEqual(["detail", "name", "ok"]);
  expect(Object.keys(s.registry).sort()).toEqual(["account", "code_hash", "events", "full_access_keys", "owner", "reproducible_build", "root"]);
  expect(Object.keys(s.receipts)).toEqual(["anchors"]);
  expect(Object.keys(s.links).sort()).toEqual(["explorer_tx", "repo"]);
  if (s.instance !== null) {
    expect(Object.keys(s.instance).sort()).toEqual(["expires_at", "key_hash", "operator", "organization", "registered_at", "registration_gas_tgas", "registration_tx"]);
  }
  if (s.replay !== null) expect(["captured_at", "checks", "code", "compose", "verdict"]).toEqual(Object.keys(s.replay).sort());
}

describe("getStatus: exit running and verified", () => {
  it("fills every section of the brief, marks green only what was checked, fetches the IP through the tunnel", async () => {
    const X: FakeExit = await startFakeExit({ operator: OPERATOR });
    closers.push(X.close);
    const now = Date.now();
    const chain = await startChain(X.registry, now);
    const ipPort = await startIpEcho("203.0.113.7");
    const s = await getStatus({
      env: {},
      exitUrl: X.url, registry: REGISTRY_ACCOUNT, trustedRoot: toHex(X.root.publicKey), rpcUrl: chain.rpc,
      nearBlocksApi: chain.blocks, archivalRpc: chain.rpc,
      replay: rawFixture(),
      egress: { host: "127.0.0.1", port: ipPort, tls: false },
    });
    expectBriefShape(s);
    expect(s.error).toBeNull();
    expect(s.exit.online).toBe(true);
    expect(s.exit.egress_ip).toBe("203.0.113.7");
    expect(s.exit.compose?.hash).toBe(X.composeHash);
    expect(s.verify.verdict).toBe("VERIFIED");
    expect(s.verify.code).toBeNull();
    expect(s.verify.root).toBe("MOCK");
    expect(s.verify.checks.length).toBeGreaterThanOrEqual(12);
    expect(s.verify.checks.every((c) => c.ok && c.detail === "")).toBe(true);
    expect(s.verify.checks.at(-2)!.name).toContain("registry re-check");
    expect(s.verify.checks.at(-1)!.name).toContain("remote DNS");
    expect(s.instance).toMatchObject({ operator: OPERATOR, key_hash: X.keyHash, registration_tx: TX_REG, registration_gas_tgas: 6 });
    expect(s.registry).toMatchObject({ account: REGISTRY_ACCOUNT, owner: DAO, root: "MOCK", code_hash: "CodeHash11111111111111111111111111111111111", full_access_keys: 0, reproducible_build: null });
    // newest first; the failed transaction is not listed; the revoke the DAO owner executed (inside its
    // act_proposal transaction) is listed with its hash and the DAO as the caller; a vote that executed nothing is not
    expect(s.registry.events.map((e) => [e.kind, e.tx, e.by])).toEqual([
      ["revoke_compose", TX_DAO_REVOKE, DAO],
      ["register_instance_tdx", TX_REG, OPERATOR],
      ["allow_compose", TX_ALLOW, OWNER],
    ]);
    expect(s.registry.events[0]!.hash).toBe("ef".repeat(32));
    expect(s.registry.events[2]!.hash).toBe("ab".repeat(32));
    expect(s.receipts.anchors).toEqual([{ id: 0, root: "cd".repeat(32), count: 4, first_seq: 0, tx: TX_ANCHOR, at: new Date(now - 1500).toISOString() }]);
    const capturedAt = new Date(JSON.parse(readFileSync(new URL(`${FIXTURE}/meta.json`, import.meta.url), "utf8")).captured_at_ms).toISOString();
    expect(s.replay).toMatchObject({ verdict: "VERIFIED", code: null, captured_at: capturedAt });
    expect(s.replay!.checks).toHaveLength(16);
  });
});

describe("getStatus: registry code-hash pin", () => {
  const CODE_LINE = "registry contract code hash matches the pinned build (view_account.code_hash)";
  const run = async (registryCodeHash: string): Promise<Status> => {
    const X: FakeExit = await startFakeExit({ operator: OPERATOR });
    closers.push(X.close);
    const chain = await startChain(X.registry, Date.now());
    return getStatus({
      env: {}, exitUrl: X.url, registry: REGISTRY_ACCOUNT, registryCodeHash, trustedRoot: toHex(X.root.publicKey), rpcUrl: chain.rpc,
      nearBlocksApi: chain.blocks, archivalRpc: chain.rpc, replay: rawFixture(), egress: null,
    });
  };

  it("match: VERIFIED and the code-hash check is in the list, before the root check", async () => {
    const s = await run("CodeHash11111111111111111111111111111111111");
    expect(s.error).toBeNull();
    expect(s.verify.verdict).toBe("VERIFIED");
    const names = s.verify.checks.map((c) => c.name);
    expect(names).toContain(CODE_LINE);
    expect(s.verify.checks[names.indexOf(CODE_LINE)]).toMatchObject({ ok: true, detail: "" });
    expect(names.indexOf(CODE_LINE)).toBeLessThan(names.findIndex((n) => n.includes("root")));
  });

  it("mismatch: REFUSED with E_REGISTRY_CODE_HASH, nothing green", async () => {
    const s = await run("4vJ9JU1bJJE96FWSJKvHsmmFADCg4gpZQff4P3bkLKi");
    expect(s.verify.verdict).toBe("REFUSED");
    expect(s.verify.code).toBe("E_REGISTRY_CODE_HASH");
    expect(s.verify.checks.find((c) => c.name === CODE_LINE)).toMatchObject({ ok: false, detail: "E_REGISTRY_CODE_HASH" });
    expect(s.verify.checks.every((c) => !c.ok)).toBe(true);
    expect(s.error).toContain("E_REGISTRY_CODE_HASH");
    expect(s.instance).toBeNull();
  });

  it("the Intel root with an unpinned registry is a configuration error", async () => {
    const s = await getStatus({ env: {}, exitUrl: "http://127.0.0.1:1", registry: REGISTRY_ACCOUNT, trustedRoot: toHex(INTEL_ROOT_P256), rpcUrl: "http://127.0.0.1:1", replay: rawFixture(), egress: null });
    expect(s.error).toContain("PLR_VPN_REGISTRY_CODE_HASH is required");
    expect(s.verify.verdict).toBe("REFUSED");
  });
});

describe("getStatus: exit stopped", () => {
  it("online false, verify REFUSED (nothing green), replay VERIFIED, registry still read", async () => {
    const X = await startFakeExit({ operator: OPERATOR });
    const chain = await startChain(X.registry, Date.now());
    const trusted = toHex(X.root.publicKey);
    await X.close();
    const s = await getStatus({
      env: {}, exitUrl: X.url, registry: REGISTRY_ACCOUNT, trustedRoot: trusted, rpcUrl: chain.rpc,
      nearBlocksApi: chain.blocks, archivalRpc: chain.rpc, replay: rawFixture(), egress: null,
      timeouts: { healthz: 1500, verify: 5000 },
    });
    expectBriefShape(s);
    expect(s.error).toBeNull();
    expect(s.exit).toMatchObject({ online: false, egress_ip: null, compose: null });
    expect(s.verify.verdict).toBe("REFUSED");
    expect(s.verify.code).toBe("E_BAD_RESPONSE");
    expect(s.verify.checks.some((c) => c.ok)).toBe(false);
    expect(s.replay?.verdict).toBe("VERIFIED");
    expect(s.replay?.compose?.logging).toBe("none");
    expect(s.registry.owner).toBe(DAO);
  });
});

describe("getStatus: registry / RPC unreachable", () => {
  it("sets error, marks nothing ok, never throws; the exit itself may still be online", async () => {
    const X = await startFakeExit({ operator: OPERATOR });
    closers.push(X.close);
    const s = await getStatus({
      env: {}, exitUrl: X.url, registry: REGISTRY_ACCOUNT, trustedRoot: toHex(X.root.publicKey), rpcUrl: "http://127.0.0.1:1",
      nearBlocksApi: "http://127.0.0.1:1/v3", archivalRpc: "http://127.0.0.1:1", replay: rawFixture(), egress: null,
      timeouts: { chain: 1500, events: 1500, verify: 8000 },
    });
    expectBriefShape(s);
    expect(s.error).toMatch(/registry unreadable/);
    expect(s.verify.verdict).toBe("REFUSED");
    expect(s.verify.checks.some((c) => c.ok)).toBe(false);
    expect(s.exit.compose).toBeNull();
    expect(s.exit.egress_ip).toBeNull();
    expect(s.instance).toBeNull();
    expect(s.registry).toMatchObject({ account: REGISTRY_ACCOUNT, owner: null, code_hash: null, events: [] });
    expect(s.receipts.anchors).toEqual([]);
  });

  it("reports a configuration problem as error instead of throwing", async () => {
    const s = await getStatus({ env: { PLR_TRUSTED_ROOT: "nope" }, exitUrl: "http://127.0.0.1:1", registry: REGISTRY_ACCOUNT, rpcUrl: "http://127.0.0.1:1", replay: rawFixture() });
    expectBriefShape(s);
    expect(s.error).toMatch(/PLR_TRUSTED_ROOT/);
    expect(s.verify.checks).toEqual([]);
    expect(s.replay?.verdict).toBe("VERIFIED");
  });

  it("reads PLR_* env variables", async () => {
    const s = await getStatus({ env: { PLR_VPN_URL: "http://127.0.0.1:1", PLR_VPN_REGISTRY: "reg.test.near", PLR_TRUSTED_ROOT: "zz", PLR_NEAR_RPC: "http://127.0.0.1:1" } });
    expect(s.error).toMatch(/PLR_TRUSTED_ROOT/);
    expect(s.registry.account).toBeNull();
  });
});
