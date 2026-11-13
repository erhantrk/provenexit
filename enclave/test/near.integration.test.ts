/**
 * Opt-in (PLR_NEAR_IT=1): the real VPN exit bundle, launched by the mock TDX host, registers itself on a
 * near-sandbox registry and anchors session receipts; proofs verify against the on-chain root.
 * Needs contracts/near/target/near/plr_registry.wasm and Unix sockets.
 */
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync } from "node:fs";
import { join, resolve } from "node:path";
import { Account, JsonRpcProvider, KeyPair, KeyPairSigner, type KeyPairString } from "near-api-js";
import { FRAME, MockRoot, fromHex, parseReceiptPayload, toHex, verifyMerkleProof, vpnReceiptLeaf } from "@plr/shared";
import { launchVpn, type VpnHostHandle } from "../src/mock-tdx/host.js";
import { TestTunnel, attestExit, startEchoUpstream } from "./vpn-helpers.js";
import { shortTmp } from "./short-tmp.js";

const ROOT_DIR = resolve(import.meta.dirname, "..", "..");
const WASM = join(ROOT_DIR, "contracts", "near", "target", "near", "plr_registry.wasm");
const enabled = process.env.PLR_NEAR_IT === "1" && existsSync(WASM);
const NEAR = 10n ** 24n;
const GAS = 300_000_000_000_000n;

describe.skipIf(!enabled)("VPN exit ↔ NEAR registry (sandbox)", () => {
  let sandbox: { rpcUrl: string; tearDown(): Promise<void> };
  let provider: JsonRpcProvider;
  let owner: Account;
  const contractId = "registry.sandbox";
  const root = MockRoot.generate();
  let host: VpnHostHandle;
  let out = "";
  let url = "";
  let runDir = "";

  const waitFor = async (re: RegExp, ms = 60_000) => {
    const end = Date.now() + ms;
    while (Date.now() < end) { const m = re.exec(out); if (m) return m; await new Promise((r) => setTimeout(r, 100)); }
    throw new Error("timeout " + re + "\n" + out);
  };

  beforeAll(async () => {
    mkdirSync(resolve(import.meta.dirname, "..", ".run"), { recursive: true });
    runDir = shortTmp("n-");
    const ns = await import("near-sandbox");
    sandbox = await ns.Sandbox.start({});
    provider = new JsonRpcProvider({ url: sandbox.rpcUrl });
    owner = new Account(ns.DEFAULT_ACCOUNT_ID, provider, KeyPairSigner.fromSecretKey(ns.DEFAULT_PRIVATE_KEY as KeyPairString));
    const kp = KeyPair.fromRandom("ed25519");
    await owner.createAccount({ newAccountId: contractId, publicKey: kp.getPublicKey().toString(), nearToTransfer: 20n * NEAR });
    const reg = new Account(contractId, provider, KeyPairSigner.fromSecretKey(kp.toString()));
    await reg.deployContract(new Uint8Array(readFileSync(WASM)));
    await reg.callFunction({ contractId, methodName: "new", args: { owner_id: owner.accountId, root_kind: "MOCK", root_p256: toHex(root.publicKey), instance_ttl_ms: 86_400_000 }, gas: GAS });

    const compose = join(ROOT_DIR, "enclave", "dist", "vpn-exit", "vpn-honest-test", "app-compose.json");
    const { measureVpnBoot } = await import("../src/mock-tdx/host.js");
    const m = await measureVpnBoot({ composePath: compose, root });
    await owner.callFunction({ contractId, methodName: "allow_compose", args: { hash: m.composeHash }, gas: GAS });
    await owner.callFunction({ contractId, methodName: "allow_os", args: { hash: m.osMeasurement }, gas: GAS });

    host = await launchVpn({
      composePath: compose, root, runDir, exitPort: 0, output: (s) => { out += s; },
      exitEnv: {
        PLR_NEAR_RPC: sandbox.rpcUrl, PLR_VPN_REGISTRY: contractId, PLR_OPERATOR_ID: owner.accountId,
        PLR_OPERATOR_KEY: ns.DEFAULT_PRIVATE_KEY, PLR_ANCHOR_INTERVAL_MS: "500",
      },
    });
    url = (await waitFor(/plr-vpn: listening url=(\S+)/))[1]!;
  }, 240_000);

  afterAll(async () => {
    try {
      await host?.stop();
      await sandbox?.tearDown().catch(() => undefined);
    } finally {
      if (runDir) rmSync(runDir, { recursive: true, force: true });
    }
  });

  it("registers at boot (under the host's permission model) and anchors receipts", async () => {
    const reg = await waitFor(/plr-vpn: (registered key_hash=\S+|registration_failed code=\S+)/);
    expect(reg[1]).toMatch(/^registered/);
    const v = await attestExit(url, root.publicKey);
    const inst = await provider.callFunction({ contractId, method: "get_instance", args: { key_hash: toHex(v.keyHash) } });
    expect(inst).toMatchObject({ x25519: toHex(v.x25519), ed25519: toHex(v.ed25519), next_seq: 0 });

    const up = await startEchoUpstream();
    const t = await TestTunnel.open(Number(new URL(url).port), v, v.nonce);
    t.connect("127.0.0.1", up.port);
    await t.until(() => t.frames.length >= 1);
    t.send(FRAME.DATA, new TextEncoder().encode("anchor me"));
    t.send(FRAME.FIN);
    expect(await t.until(() => t.types().includes(FRAME.RECEIPT))).toBe(true);
    const receipt = parseReceiptPayload(t.frames.find((f) => f.type === FRAME.RECEIPT)!.payload).receipt;
    await up.close();
    expect(receipt.seq).toBe(0);
    let proof: { anchor_id: number; index: number; count: number; root: string; proof: string[] } | null = null;
    for (let i = 0; i < 60 && !proof; i++) {
      const res = await fetch(`${url}/v1/receipts/proof?seq=0`);
      if (res.status === 200) proof = await res.json();
      else await new Promise((r) => setTimeout(r, 500));
    }
    expect(proof, out).not.toBeNull();
    const anchor = (await provider.callFunction({ contractId, method: "get_anchor", args: { id: proof!.anchor_id } })) as { root: string; key_hash: string };
    expect(anchor.root).toBe(proof!.root);
    expect(anchor.key_hash).toBe(toHex(v.keyHash));
    expect(verifyMerkleProof(vpnReceiptLeaf(receipt), proof!.index, proof!.count, proof!.proof.map((h) => fromHex(h, 32)), fromHex(anchor.root, 32))).toBe(true);
    expect(out).not.toContain("anchor me");
  }, 120_000);
});
