/**
 * EVM chain driver (tier B, SPEC-CHAINS §6, §9): one `anvil` per stack on a free 127.0.0.1 port (automine: every
 * transaction is mined on arrival), with two independent `PlrRegistry` deployments — the LLM registry and the VPN
 * registry — owned by the same fresh owner account, MOCK root = the stack's pinned root, TTL = the stack's.
 *
 * Accounts: fresh secp256k1 keys for owner, operator, operator2 and stranger, each funded with `anvil_setBalance`.
 * Owner writes (`ChainAdmin`) are signed transactions that resolve once mined (a stranger's are refused by the
 * contract: they reject at gas estimation). The instance env is exactly SPEC-CHAINS §9: `PLR_CHAIN=evm`, `PLR_EVM_RPC`,
 * `PLR_EVM_REGISTRY` / `PLR_EVM_VPN_REGISTRY` and the operator's `PLR_EVM_KEY` (the writer asks the node for the chain id; one key per operator address on EVM:
 * the writer retries nonce conflicts between TDs of one operator).
 *
 * The contract artifact comes from `forge build` in contracts/evm (`out/PlrRegistry.sol/PlrRegistry.json`).
 * The reader is injected (`deps.createReader`, normally `(o) => new EvmRegistry(o)` from @plr/client) so this file
 * does not depend on how the client package exports it.
 */
import { existsSync, readFileSync } from "node:fs";
import { mkdir } from "node:fs/promises";
import { homedir } from "node:os";
import { delimiter, dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import {
  createPublicClient,
  createWalletClient,
  defineChain,
  http,
  parseAbi,
  type Abi,
  type Account,
  type Address,
  type Chain as ViemChain,
  type Hex,
  type HttpTransport,
  type PublicClient,
  type WalletClient,
} from "viem";
import { generatePrivateKey, privateKeyToAccount } from "viem/accounts";
import { isHash32, isOrgId, toHex, type RegistryReader } from "@plr/shared";
import { startManaged, waitFor, type ManagedProcess } from "../procs.js";
import { freePort } from "../sandbox.js";
import { OPERATORS, type CallFn, type ChainAdmin, type ChainDriver, type DriverOptions, type OperatorAccount, type RegistryName, type Signer } from "./driver.js";

const REPO_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..", "..", "..");
export const EVM_ARTIFACT = join(REPO_ROOT, "contracts", "evm", "out", "PlrRegistry.sol", "PlrRegistry.json");
/** anvil's default chain id. */
export const EVM_CHAIN_ID = 31337;
const FUNDING_WEI = 10n ** 24n; // 1 000 000 ETH
const RPC_TIMEOUT_MS = 15_000;
const CONFIRM_TIMEOUT_MS = 60_000;
const MAX_SEND_ATTEMPTS = 8;

/** Owner-side ABI subset the driver calls (the contract's full ABI comes from the artifact). */
const OWNER_ABI = parseAbi([
  "function allowCompose(bytes32 h)",
  "function revokeCompose(bytes32 h)",
  "function allowOs(bytes32 h)",
  "function revokeOs(bytes32 h)",
  "function approveOperator(address op, string orgId)",
  "function revokeOperator(address op)",
  "function contractId() view returns (string)",
]);

/** Builds the stack's reader of one registry. */
export type EvmReaderFactory = (o: { rpcUrl: string; chainId: number; address: string }) => RegistryReader;
export interface EvmDriverDeps {
  createReader: EvmReaderFactory;
}

/** `anvil` to use: `ANVIL_BIN`, else `~/.foundry/bin/anvil`, else the first `anvil` on PATH; null if none. */
export function anvilBinary(): string | null {
  const fromEnv = process.env.ANVIL_BIN;
  if (fromEnv) return existsSync(fromEnv) ? fromEnv : null;
  const foundry = join(homedir(), ".foundry", "bin", "anvil");
  if (existsSync(foundry)) return foundry;
  for (const d of [...(process.env.PATH ?? "").split(delimiter), "/opt/homebrew/bin", "/usr/local/bin"]) {
    if (d && existsSync(join(d, "anvil"))) return join(d, "anvil");
  }
  return null;
}

/** ABI + creation bytecode of `PlrRegistry` from the Foundry artifact. */
export function loadEvmArtifact(path = EVM_ARTIFACT): { abi: Abi; bytecode: Hex } {
  if (!existsSync(path)) throw new Error(`PlrRegistry artifact missing (${path}); run: cd contracts/evm && forge build`);
  const j = JSON.parse(readFileSync(path, "utf8")) as { abi?: unknown; bytecode?: { object?: unknown } };
  const bytecode = j.bytecode?.object;
  if (!Array.isArray(j.abi) || typeof bytecode !== "string" || !/^0x(?:[0-9a-f]{2})+$/i.test(bytecode)) throw new Error(`malformed artifact: ${path}`);
  return { abi: j.abi as Abi, bytecode: bytecode as Hex };
}

const nonceConflict = (e: unknown): boolean =>
  /nonce too low|nonce too high|already known|replacement transaction underpriced|invalid nonce/i.test(e instanceof Error ? `${e.message}\n${String((e as { details?: unknown }).details ?? "")}` : String(e));

/** One signing account with a serialized send queue (fresh `pending` nonce per send, nonce conflicts retried). */
class EvmSigner {
  readonly account: Account;
  readonly address: string;
  readonly wallet: WalletClient<HttpTransport, ViemChain, Account>;
  #queue: Promise<unknown> = Promise.resolve();
  constructor(readonly secretKey: Hex, readonly pub: PublicClient<HttpTransport, ViemChain>, chain: ViemChain, transport: HttpTransport) {
    this.account = privateKeyToAccount(secretKey);
    this.address = this.account.address.toLowerCase();
    this.wallet = createWalletClient({ chain, transport, account: this.account });
  }

  /** Sends one contract call and waits until it is mined; rejects on revert (incl. at gas estimation). */
  call(address: string, fn: string, args: readonly unknown[], abi: Abi = OWNER_ABI): Promise<void> {
    const run = this.#queue.then(async () => {
      for (let attempt = 1; ; attempt++) {
        try {
          const nonce = await this.pub.getTransactionCount({ address: this.account.address, blockTag: "pending" });
          const hash = await this.wallet.writeContract({ address: address as Address, abi, functionName: fn, args, nonce } as never);
          const r = await this.pub.waitForTransactionReceipt({ hash, timeout: CONFIRM_TIMEOUT_MS, pollingInterval: 100 });
          if (r.status !== "success") throw new Error(`${fn} reverted`);
          return;
        } catch (e) {
          if (attempt < MAX_SEND_ATTEMPTS && nonceConflict(e)) {
            await new Promise((ok) => setTimeout(ok, 50 * attempt));
            continue;
          }
          throw e;
        }
      }
    });
    this.#queue = run.catch(() => undefined);
    return run;
  }
}

/** The contract call of a NEAR-style owner method (`stack-cli owner`, `call` / `callVpn`). */
export function evmOwnerCallOf(method: string, args: object): { fn: string; args: unknown[] } {
  const o = args as Record<string, unknown>;
  const hash = (): Hex => {
    if (typeof o.hash !== "string" || !isHash32(o.hash)) throw new Error(`${method} failed: hash must be 64 lowercase hex`);
    return `0x${o.hash}`;
  };
  const account = (): Hex => {
    if (typeof o.account_id !== "string" || !/^0x[0-9a-fA-F]{40}$/.test(o.account_id)) throw new Error(`${method} failed: account_id must be a 0x address`);
    return o.account_id.toLowerCase() as Hex;
  };
  switch (method) {
    case "allow_compose":
      return { fn: "allowCompose", args: [hash()] };
    case "revoke_compose":
      return { fn: "revokeCompose", args: [hash()] };
    case "allow_os":
      return { fn: "allowOs", args: [hash()] };
    case "revoke_os":
      return { fn: "revokeOs", args: [hash()] };
    case "approve_operator":
      if (typeof o.org_id !== "string" || !isOrgId(o.org_id)) throw new Error(`${method} failed: bad org_id`);
      return { fn: "approveOperator", args: [account(), o.org_id] };
    case "revoke_operator":
      return { fn: "revokeOperator", args: [account()] };
    default:
      throw new Error(`${method} failed: not an owner method of the EVM registry`);
  }
}

function viemChain(chainId: number): ViemChain {
  return defineChain({ id: chainId, name: `evm-${chainId}`, nativeCurrency: { name: "Ether", symbol: "ETH", decimals: 18 }, rpcUrls: { default: { http: [] } } });
}

/** Sends one owner method with `secretKey` and waits until it is mined (`stack-cli owner` on an EVM stack). */
export async function postEvmOwnerCall(o: { rpcUrl: string; chainId: number; registry: string; secretKey: string }, method: string, args: object): Promise<{ signer: string }> {
  const chain = viemChain(o.chainId);
  const transport = http(o.rpcUrl, { timeout: RPC_TIMEOUT_MS });
  const pub = createPublicClient({ chain, transport });
  // The owner file stores the secret as 64 hex without 0x (like PLR_EVM_KEY); accept both.
  const raw = o.secretKey.startsWith("0x") ? o.secretKey.slice(2) : o.secretKey;
  if (!/^[0-9a-fA-F]{64}$/.test(raw)) throw new Error(`${method} failed: malformed owner key`);
  const s = new EvmSigner(`0x${raw}`, pub, chain, transport);
  const c = evmOwnerCallOf(method, args);
  await s.call(o.registry, c.fn, c.args);
  return { signer: s.address };
}

export async function startEvmDriver(o: DriverOptions, deps: EvmDriverDeps): Promise<ChainDriver> {
  const bin = anvilBinary();
  if (bin === null) throw new Error("anvil not found (install Foundry, or set ANVIL_BIN)");
  const { abi, bytecode } = loadEvmArtifact();
  const dir = join(o.dir, "evm");
  await mkdir(dir, { recursive: true, mode: 0o700 });
  const rpcPort = o.rpcPort ?? (await freePort());
  const rpcUrl = `http://127.0.0.1:${rpcPort}`;
  const chainId = EVM_CHAIN_ID;

  const proc: ManagedProcess = startManaged({
    name: "anvil",
    cmd: bin,
    args: ["--host", "127.0.0.1", "--port", String(rpcPort), "--chain-id", String(chainId), "--accounts", "0", "--silent"],
    env: { PATH: process.env.PATH ?? "/usr/bin:/bin", HOME: dir },
    cwd: dir,
    maxOutput: 256 * 1024,
    graceMs: 3000,
  });
  let stopped: Promise<void> | null = null;
  const stop = (): Promise<void> => (stopped ??= proc.stop().then(() => undefined));
  try {
    const chain = viemChain(chainId);
    const transport = http(rpcUrl, { timeout: RPC_TIMEOUT_MS, retryCount: 1 });
    const pub = createPublicClient({ chain, transport, pollingInterval: 100 });
    await waitFor("anvil RPC", async () => {
      if (proc.exited) throw new Error(`anvil exited early:\n${proc.output().slice(-4000)}`);
      return pub.getChainId().then((id) => (id === chainId ? (true as const) : undefined), () => undefined);
    }, 60_000, 100);

    const signers: Record<Signer, EvmSigner> = {
      owner: new EvmSigner(generatePrivateKey(), pub, chain, transport),
      operator: new EvmSigner(generatePrivateKey(), pub, chain, transport),
      operator2: new EvmSigner(generatePrivateKey(), pub, chain, transport),
      stranger: new EvmSigner(generatePrivateKey(), pub, chain, transport),
    };
    for (const s of Object.values(signers)) {
      await pub.request({ method: "anvil_setBalance" as never, params: [s.address, `0x${FUNDING_WEI.toString(16)}`] as never });
    }

    // Both registries: same bytecode, owner and MOCK root; independent allowlists, instances and anchors.
    const deploy = async (): Promise<string> => {
      const owner = signers.owner;
      const hash = await owner.wallet.deployContract({ abi, bytecode, args: [owner.address, 1, `0x${toHex(o.trustedRoot)}`, BigInt(o.instanceTtlMs)] } as never);
      const r = await pub.waitForTransactionReceipt({ hash, timeout: CONFIRM_TIMEOUT_MS, pollingInterval: 100 });
      if (r.status !== "success" || !r.contractAddress) throw new Error("PlrRegistry deployment failed");
      return r.contractAddress.toLowerCase();
    };
    const llmAddress = await deploy();
    const vpnAddress = await deploy();
    const contractId = `evm:${chainId}:${llmAddress}`;
    const vpnContractId = `evm:${chainId}:${vpnAddress}`;
    for (const [addr, cid] of [[llmAddress, contractId], [vpnAddress, vpnContractId]] as const) {
      const got = await pub.readContract({ address: addr as Address, abi: OWNER_ABI, functionName: "contractId" });
      if (got !== cid) throw new Error(`PlrRegistry.contractId() = ${got}, expected ${cid}`);
    }
    const addressOf = (reg: RegistryName) => (reg === "llm" ? llmAddress : vpnAddress);

    const registry = deps.createReader({ rpcUrl, chainId, address: llmAddress });
    const vpnRegistry = deps.createReader({ rpcUrl, chainId, address: vpnAddress });
    if (registry.contractId !== contractId || vpnRegistry.contractId !== vpnContractId) throw new Error("EVM reader contractId mismatch");

    const signerOf = (signer: Signer): EvmSigner => {
      const s = signers[signer];
      if (!s) throw new Error(`unknown signer: ${String(signer)}`);
      return s;
    };
    const operatorAddress = (account: OperatorAccount): string => {
      if (!OPERATORS.includes(account)) throw new Error(`unknown operator account: ${String(account)}`);
      return signers[account].address;
    };
    const send = async (reg: RegistryName, signer: Signer, fn: string, args: readonly unknown[]): Promise<void> => {
      if (stopped) throw new Error("stack is stopped");
      await signerOf(signer).call(addressOf(reg), fn, args);
    };
    const adminOf = new WeakMap<ChainAdmin, RegistryName>();
    const makeAdmin = (reg: RegistryName, signer: Signer): ChainAdmin => {
      const h = (x: string): Hex => {
        if (!isHash32(x)) throw new Error("hash must be 64 lowercase hex (not zero)");
        return `0x${x}`;
      };
      const a: ChainAdmin = {
        allowCompose: (x) => send(reg, signer, "allowCompose", [h(x)]),
        revokeCompose: (x) => send(reg, signer, "revokeCompose", [h(x)]),
        allowOs: (x) => send(reg, signer, "allowOs", [h(x)]),
        revokeOs: (x) => send(reg, signer, "revokeOs", [h(x)]),
        approveOperator: (account, orgId) => send(reg, signer, "approveOperator", [operatorAddress(account), orgId]),
        revokeOperator: (account) => send(reg, signer, "revokeOperator", [operatorAddress(account)]),
      };
      adminOf.set(a, reg);
      return a;
    };
    const callOn = (reg: RegistryName): CallFn => async (signer, method, args) => {
      try {
        const c = evmOwnerCallOf(method, args);
        await send(reg, signer, c.fn, c.args);
      } catch (e) {
        const msg = e instanceof Error ? e.message : String(e);
        throw new Error(msg.startsWith(`${method} failed`) ? msg : `${method} failed: ${msg.split("\n")[0]}`);
      }
      return undefined;
    };

    return {
      chain: "evm",
      rpcUrl,
      contractId,
      vpnContractId,
      registry,
      vpnRegistry,
      accounts: { owner: signers.owner.address, operator: signers.operator.address, operator2: signers.operator2.address, stranger: signers.stranger.address },
      admin: makeAdmin("llm", "owner"),
      vpnAdmin: makeAdmin("vpn", "owner"),
      asStranger: (a) => {
        const reg = adminOf.get(a);
        if (reg === undefined) throw new Error("asStranger: not an admin of this stack");
        return makeAdmin(reg, "stranger");
      },
      view: async <T>(method: string, args: object): Promise<T> => {
        // camelCase view of the LLM registry, positional args in key order (e.g. view("getOperator", { op })).
        return (await pub.readContract({ address: llmAddress as Address, abi, functionName: method, args: Object.values(args) } as never)) as T;
      },
      call: callOn("llm"),
      callVpn: callOn("vpn"),
      instanceEnv: async (op, registries) => ({
        PLR_CHAIN: "evm",
        PLR_EVM_RPC: rpcUrl,
        ...(registries.includes("llm") ? { PLR_EVM_REGISTRY: llmAddress } : {}),
        ...(registries.includes("vpn") ? { PLR_EVM_VPN_REGISTRY: vpnAddress } : {}),
        PLR_EVM_KEY: signers[op].secretKey.slice(2),
      }),
      clientEnvLines: () => [
        "PLR_CHAIN=evm",
        `PLR_EVM_RPC=${rpcUrl}`,
        `PLR_REGISTRY=${contractId}`,
        `PLR_VPN_REGISTRY=${vpnContractId}`,
      ],
      ownerFile: () => ({
        chain: "evm",
        rpc_url: rpcUrl,
        chain_id: chainId,
        registry: llmAddress,
        vpn_registry: vpnAddress,
        owner: { address: signers.owner.address, secret_key: signers.owner.secretKey.slice(2) },
      }),
      exportSigner: (signer) => {
        const s = signerOf(signer);
        return { accountId: s.address, secretKey: s.secretKey.slice(2) };
      },
      stop,
    };
  } catch (e) {
    await stop();
    throw e;
  }
}
