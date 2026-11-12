/**
 * NEAR chain driver: a fresh near-sandbox under the stack's run dir with the VPN registry deployed (the
 * contracts/near wasm, MOCK root). Accounts: vpnregistry (the contract), owner, operator, operator2, stranger — each
 * with its own fresh key.
 */
import { existsSync, readFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { Account, JsonRpcProvider, KeyPair, KeyPairSigner, type KeyPairString } from "near-api-js";
import { toHex } from "@plr/shared";
import { NearRegistry } from "@plr/client";
import { startSandbox, type SandboxNode } from "../sandbox.js";
import { OPERATORS, type CallFn, type ChainAdmin, type ChainDriver, type DriverOptions, type OperatorAccount, type Signer } from "./driver.js";

const REPO_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..", "..", "..");
export const REGISTRY_WASM = join(REPO_ROOT, "contracts", "near", "target", "near", "plr_registry.wasm");

const NEAR = 10n ** 24n;
const DEFAULT_GAS = 300_000_000_000_000n;

export async function startNearDriver(o: DriverOptions): Promise<ChainDriver> {
  if (!existsSync(REGISTRY_WASM)) throw new Error(`registry wasm missing (${REGISTRY_WASM}); run: cd contracts/near && cargo near build non-reproducible-wasm --no-abi`);
  const node: SandboxNode = await startSandbox({ homeDir: join(o.dir, "near"), ...(o.rpcPort !== undefined ? { rpcPort: o.rpcPort } : {}) });
  try {
    const rpcUrl = node.rpcUrl;
    const provider = new JsonRpcProvider({ url: rpcUrl });
    const rootAcct = new Account(node.rootAccountId, provider, KeyPairSigner.fromSecretKey(node.rootKey));

    const names = {
      vpnregistry: `vpnregistry.${node.rootAccountId}`,
      owner: `owner.${node.rootAccountId}`,
      operator: `operator.${node.rootAccountId}`,
      operator2: `operator2.${node.rootAccountId}`,
      stranger: `stranger.${node.rootAccountId}`,
    };
    type Role = keyof typeof names;
    const keys = new Map<string, KeyPair>();
    for (const [role, accountId] of Object.entries(names)) {
      const kp = KeyPair.fromRandom("ed25519");
      keys.set(role, kp);
      const isContract = role === "vpnregistry";
      await rootAcct.createAccount({ newAccountId: accountId, publicKey: kp.getPublicKey().toString(), nearToTransfer: (isContract ? 50n : 100n) * NEAR });
    }
    const acct = (role: Role) => new Account(names[role], provider, KeyPairSigner.fromSecretKey(keys.get(role)!.toString() as KeyPairString));
    const signers: Record<Signer, Account> = { owner: acct("owner"), operator: acct("operator"), operator2: acct("operator2"), stranger: acct("stranger") };
    const vpnContractId = names.vpnregistry;

    // The registry: the contracts/near wasm, the stack owner and the MOCK root.
    const wasm = new Uint8Array(readFileSync(REGISTRY_WASM));
    const reg = acct("vpnregistry");
    await reg.deployContract(wasm);
    await reg.callFunction({
      contractId: vpnContractId,
      methodName: "new",
      args: { owner_id: names.owner, root_kind: "MOCK", root_p256: toHex(o.trustedRoot), instance_ttl_ms: o.instanceTtlMs },
      gas: DEFAULT_GAS,
    });

    const vpnRegistry = new NearRegistry({ rpcUrl, contractId: vpnContractId });

    const viewVpn = async <T>(method: string, args: object): Promise<T> => {
      const raw = await provider.callFunctionRaw({ contractId: vpnContractId, method, args: args as Record<string, unknown>, blockQuery: { finality: "optimistic" } });
      const bytes = new Uint8Array(raw.result);
      if (bytes.length === 0) return undefined as T;
      return JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(bytes)) as T;
    };

    const callOn = (target: string): CallFn => async (signer, method, args, co = {}) => {
      const a = signers[signer];
      if (!a) throw new Error(`unknown signer: ${String(signer)}`);
      const amount = (v: string | undefined, def: bigint, what: string): bigint => {
        if (v === undefined) return def;
        if (!/^[0-9]{1,40}$/.test(v)) throw new Error(`call: bad ${what}`);
        return BigInt(v);
      };
      try {
        return await a.callFunction({ contractId: target, methodName: method, args: args as Record<string, unknown>, gas: amount(co.gas, DEFAULT_GAS, "gas"), deposit: amount(co.deposit, 0n, "deposit") });
      } catch (e) {
        const msg = e instanceof Error ? e.message : String(e);
        const err = new Error(`${method} failed: ${msg}`);
        (err as Error & { cause?: unknown }).cause = e;
        throw err;
      }
    };
    const callVpn = callOn(vpnContractId);

    const operatorId = (account: OperatorAccount): string => {
      if (!OPERATORS.includes(account)) throw new Error(`unknown operator account: ${String(account)}`);
      return names[account];
    };
    const admins = new WeakSet<ChainAdmin>();
    const makeAdmin = (signer: Signer): ChainAdmin => {
      const c = callVpn;
      const a: ChainAdmin = {
        allowCompose: async (h) => void (await c(signer, "allow_compose", { hash: h })),
        revokeCompose: async (h) => void (await c(signer, "revoke_compose", { hash: h })),
        allowOs: async (h) => void (await c(signer, "allow_os", { hash: h })),
        revokeOs: async (h) => void (await c(signer, "revoke_os", { hash: h })),
        approveOperator: async (account, orgId) => void (await c(signer, "approve_operator", { account_id: operatorId(account), org_id: orgId })),
        revokeOperator: async (account) => void (await c(signer, "revoke_operator", { account_id: operatorId(account) })),
      };
      admins.add(a);
      return a;
    };
    const vpnAdmin = makeAdmin("owner");

    let stopped: Promise<void> | null = null;
    return {
      rpcUrl,
      vpnContractId,
      vpnRegistry,
      accounts: { owner: names.owner, operator: names.operator, operator2: names.operator2, stranger: names.stranger },
      vpnAdmin,
      asStranger: (a) => {
        if (!admins.has(a)) throw new Error("asStranger: not an admin of this stack");
        return makeAdmin("stranger");
      },
      viewVpn,
      callVpn,
      instanceEnv: async (op) => {
        // A dedicated full-access key per TD on the operator account: no nonce races between TDs or with the
        // harness's own operator calls (near-api-js retries InvalidNonce).
        // Function-call keys cannot attach the storage deposit. PLR_OPERATOR_ID is the account the enclave binds
        // into its registration quote (SPEC §5 rev 1.3): only that account can submit it.
        const instanceKey = KeyPair.fromRandom("ed25519");
        await signers[op].addFullAccessKey(instanceKey.getPublicKey().toString());
        return {
          PLR_NEAR_RPC: rpcUrl,
          PLR_VPN_REGISTRY: vpnContractId,
          PLR_OPERATOR_ID: operatorId(op),
          PLR_OPERATOR_KEY: instanceKey.toString(),
        };
      },
      clientEnvLines: () => [`PLR_NEAR_RPC=${rpcUrl}`, `PLR_VPN_REGISTRY=${vpnContractId}`],
      ownerFile: () => ({ account_id: names.owner, secret_key: keys.get("owner")!.toString() }),
      exportSigner: (signer) => {
        const kp = keys.get(signer);
        if (!kp || !(signer in signers)) throw new Error(`unknown signer: ${String(signer)}`);
        return { accountId: names[signer], secretKey: kp.toString() };
      },
      stop: () => (stopped ??= node.stop()),
    };
  } catch (e) {
    await node.stop();
    throw e;
  }
}
