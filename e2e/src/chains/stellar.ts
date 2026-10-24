/**
 * Stellar chain driver (tier B, SPEC-CHAINS §6, §10; facts in docs/stellar-local.md): one local quickstart container
 * per stack (`stellar container start local --name <unique> -p <port>:8000 --protocol-version 29 --limits unlimited`),
 * removed again by `stop()` (the CLI runs it with `--rm`).
 *
 * Boot: wait for RPC `getHealth` = healthy and for friendbot to fund (bounded), fund fresh keypairs for owner,
 * operator, operator2 and stranger, upload contracts/stellar's wasm and create two independent registries (LLM + VPN,
 * same owner and MOCK root) through their `__constructor`. Owner writes are invocations signed by the owner
 * (`owner.require_auth()` through source-account authorization) and resolve once the transaction succeeded. A
 * stranger's owner call needs the owner's authorization, which it cannot provide: it is refused before submission.
 *
 * The registry readers come from the caller (`deps.reader`, i.e. `@plr/client`'s StellarRegistry) so this file does
 * not depend on exports that are wired separately.
 */
import { execFile } from "node:child_process";
import { existsSync, readFileSync } from "node:fs";
import { randomBytes } from "node:crypto";
import { dirname, delimiter, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { Account, Address, Keypair, Operation, StrKey, TransactionBuilder, hash, rpc, xdr } from "@stellar/stellar-sdk";
import { isHash32, toHex, type RegistryReader } from "@plr/shared";
import { waitFor } from "../procs.js";
import { freePort } from "../sandbox.js";
import { OPERATORS, type CallFn, type ChainAdmin, type ChainDriver, type DriverOptions, type OperatorAccount, type RegistryName, type Signer } from "./driver.js";

const REPO_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..", "..", "..");
export const STELLAR_REGISTRY_WASM = join(REPO_ROOT, "contracts", "stellar", "target", "wasm32v1-none", "release", "plr_stellar_registry.wasm");
export const STELLAR_PASSPHRASE = "Standalone Network ; February 2017";
const NULL_ACCOUNT = "GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAWHF";
const RPC_TIMEOUT_MS = 15_000;
const CONFIRM_TIMEOUT_MS = 60_000;
const HEALTH_TIMEOUT_MS = 240_000;
const FRIENDBOT_TIMEOUT_MS = 180_000;
const CLI_TIMEOUT_MS = 180_000;
const MAX_SUBMIT_ATTEMPTS = 6;
const STELLAR_ERRORS = [
  "E_UNAUTHORIZED", "E_ZERO_HASH", "E_BAD_INPUT", "E_OPERATOR_UNAPPROVED", "E_REPORT_DATA", "E_QUOTE_FORMAT", "E_SEQ",
  "E_INSTANCE_NOT_REGISTERED", "E_COMPOSE_NOT_ALLOWED",
] as const;

const sleep = (ms: number) => new Promise<void>((ok) => setTimeout(ok, ms));

/** `stellar` CLI to use: `STELLAR_BIN`, else /opt/homebrew/bin/stellar, else the first on PATH; null if none. */
export function stellarBinary(): string | null {
  const fromEnv = process.env.STELLAR_BIN;
  if (fromEnv) return existsSync(fromEnv) ? fromEnv : null;
  for (const d of ["/opt/homebrew/bin", "/usr/local/bin", ...(process.env.PATH ?? "").split(delimiter)]) {
    if (d && existsSync(join(d, "stellar"))) return join(d, "stellar");
  }
  return null;
}

function run(bin: string, args: string[], timeoutMs: number): Promise<{ stdout: string; stderr: string }> {
  return new Promise((ok, fail) => {
    execFile(bin, args, { timeout: timeoutMs, maxBuffer: 4 * 1024 * 1024, env: process.env }, (err, stdout, stderr) => {
      if (err) fail(new Error(`${[bin, ...args].join(" ")} failed: ${err.message}\n${String(stderr).slice(-2000)}`));
      else ok({ stdout: String(stdout), stderr: String(stderr) });
    });
  });
}

/** `Error(Contract, #n)` → SPEC-CHAINS §10 name. */
function contractErrorOf(text: string): string | null {
  const m = /Error\(Contract, #(\d{1,4})\)/.exec(text);
  const n = m ? Number(m[1]) : 0;
  return n >= 1 && n <= STELLAR_ERRORS.length ? STELLAR_ERRORS[n - 1]! : null;
}

const scvBytesN = (hex: string): xdr.ScVal => xdr.ScVal.scvBytes(Uint8Array.from(Buffer.from(hex, "hex")));

// ------------------------------------------------------------------------------------------------ transactions

/** Harness-side Soroban client: simulate → assemble → sign → send → poll, with node messages in errors (diagnostics). */
export class StellarSubmitter {
  readonly server: rpc.Server;
  constructor(readonly rpcUrl: string, readonly passphrase: string = STELLAR_PASSPHRASE) {
    this.server = new rpc.Server(rpcUrl, { allowHttp: rpcUrl.startsWith("http:"), timeout: RPC_TIMEOUT_MS });
  }

  /** Read-only invocation (simulation only). */
  async view(contract: string, method: string, args: xdr.ScVal[] = []): Promise<xdr.ScVal> {
    const op = Operation.invokeContractFunction({ contract, function: method, args });
    const tx = new TransactionBuilder(new Account(NULL_ACCOUNT, "0"), { fee: "100", networkPassphrase: this.passphrase }).addOperation(op).setTimeout(0).build();
    const sim = await this.server.simulateTransaction(tx);
    if (rpc.Api.isSimulationError(sim)) throw new Error(`${method} failed: ${contractErrorOf(sim.error) ?? sim.error.slice(0, 400)}`);
    const ret = sim.result?.retval;
    if (ret === undefined) throw new Error(`${method}: no result`);
    return ret;
  }

  /** Submits `op` with `kp` as source; resolves with the return value once it succeeded. */
  async submit(kp: Keypair, op: xdr.Operation, what: string): Promise<xdr.ScVal | undefined> {
    let last = "";
    for (let attempt = 0; attempt < MAX_SUBMIT_ATTEMPTS; attempt++) {
      const account = await this.server.getAccount(kp.publicKey());
      const tx = new TransactionBuilder(account, { fee: "10000", networkPassphrase: this.passphrase }).addOperation(op).setTimeout(120).build();
      const sim = await this.server.simulateTransaction(tx);
      if (rpc.Api.isSimulationError(sim)) throw new Error(`${what} failed: ${contractErrorOf(sim.error) ?? sim.error.slice(0, 400)}`);
      // Authorization by any account other than the source (e.g. the owner, for a stranger's owner call) cannot be
      // given by this signer: refused here instead of failing on chain.
      if ((sim.result?.auth ?? []).some((a) => a.credentials.type !== "sorobanCredentialsSourceAccount")) {
        throw new Error(`${what} failed: E_UNAUTHORIZED (requires another account's authorization)`);
      }
      const prepared = rpc.assembleTransaction(tx, sim).build();
      prepared.sign(kp);
      const sent = await this.server.sendTransaction(prepared);
      if (sent.status === "PENDING" || sent.status === "DUPLICATE") {
        const deadline = Date.now() + CONFIRM_TIMEOUT_MS;
        for (;;) {
          const r = await this.server.getTransaction(sent.hash).catch(() => null);
          if (r?.status === rpc.Api.GetTransactionStatus.SUCCESS) return r.returnValue;
          if (r?.status === rpc.Api.GetTransactionStatus.FAILED) {
            last = "transaction failed";
            break;
          }
          if (Date.now() > deadline) throw new Error(`${what} failed: not confirmed in ${CONFIRM_TIMEOUT_MS} ms`);
          await sleep(300);
        }
      } else {
        last = `${sent.status}${sent.errorResult ? ` ${sent.errorResult.result.type}` : ""}`;
        if (sent.status === "ERROR" && sent.errorResult?.result.type !== "txBadSeq") break;
      }
      await sleep(300 * (attempt + 1));
    }
    throw new Error(`${what} failed: ${last}`);
  }

  invoke(kp: Keypair, contract: string, method: string, args: xdr.ScVal[]): Promise<xdr.ScVal | undefined> {
    return this.submit(kp, Operation.invokeContractFunction({ contract, function: method, args }), method);
  }

  /** Uploads `wasm` (idempotent) and returns its hash. */
  async upload(kp: Keypair, wasm: Uint8Array): Promise<Uint8Array> {
    await this.submit(kp, Operation.uploadContractWasm({ wasm }), "upload wasm");
    return hash(wasm);
  }

  /** Creates a registry instance through its constructor; returns its `C…` strkey. */
  async deployRegistry(kp: Keypair, wasmHash: Uint8Array, owner: string, rootP256: Uint8Array, ttlMs: number): Promise<string> {
    if (rootP256.length !== 64) throw new Error("deploy: root must be 64 bytes");
    const ret = await this.submit(
      kp,
      Operation.createCustomContract({
        address: new Address(kp.publicKey()),
        wasmHash,
        salt: new Uint8Array(randomBytes(32)),
        constructorArgs: [new Address(owner).toScVal(), xdr.ScVal.scvU32(1), xdr.ScVal.scvBytes(rootP256), xdr.ScVal.scvU64(BigInt(ttlMs))],
      }),
      "deploy registry",
    );
    if (ret === undefined || ret.type !== "scvAddress") throw new Error("deploy registry: no contract address returned");
    const c = Address.fromScVal(ret).toString();
    if (!StrKey.isValidContract(c)) throw new Error("deploy registry: bad contract address");
    return c;
  }
}

// ------------------------------------------------------------------------------------------------ node

export interface StellarNode {
  readonly name: string;
  readonly port: number;
  readonly rpcUrl: string;
  readonly friendbotUrl: string;
  stop(): Promise<void>;
}

/** Starts a fresh local network container and waits until RPC is healthy and friendbot funds (bounded). */
export async function startStellarNode(o: { rpcPort?: number } = {}): Promise<StellarNode> {
  const bin = stellarBinary();
  if (!bin) throw new Error("stellar CLI not found (set STELLAR_BIN)");
  const port = o.rpcPort ?? (await freePort());
  const name = `plr-${Date.now().toString(36)}-${randomBytes(3).toString("hex")}`;
  const base = `http://localhost:${port}`;
  let stopped: Promise<void> | null = null;
  const stop = (): Promise<void> =>
    (stopped ??= run(bin, ["container", "stop", name], 60_000).then(() => undefined, () => undefined));
  await run(bin, ["container", "start", "local", "--name", name, "-p", `${port}:8000`, "--protocol-version", "29", "--limits", "unlimited"], CLI_TIMEOUT_MS);
  try {
    const rpcUrl = `${base}/rpc`;
    const server = new rpc.Server(rpcUrl, { allowHttp: true, timeout: 5_000 });
    await waitFor("stellar RPC healthy", async () => {
      const h = await server.getHealth().catch(() => null);
      return h?.status === "healthy" ? true : undefined;
    }, HEALTH_TIMEOUT_MS, 1000);
    return { name, port, rpcUrl, friendbotUrl: `${base}/friendbot`, stop };
  } catch (e) {
    await stop();
    throw e;
  }
}

/** Funds `account` with friendbot, retrying until friendbot is up (bounded). */
export async function fund(node: StellarNode, account: string, timeoutMs = FRIENDBOT_TIMEOUT_MS): Promise<void> {
  const server = new rpc.Server(node.rpcUrl, { allowHttp: true, timeout: 5_000 });
  await waitFor(`friendbot funds ${account}`, async () => {
    const r = await fetch(`${node.friendbotUrl}?addr=${encodeURIComponent(account)}`, { signal: AbortSignal.timeout(15_000) }).catch(() => null);
    await r?.arrayBuffer().catch(() => undefined);
    const exists = await server.getAccount(account).then(() => true, () => false);
    return exists ? true : undefined;
  }, timeoutMs, 1000);
}

// ------------------------------------------------------------------------------------------------ driver

export interface StellarDriverDeps {
  /** Registry reader factory (the harness passes `new StellarRegistry(o)` from @plr/client). */
  reader(o: { rpcUrl: string; networkPassphrase: string; contract: string }): RegistryReader;
}

export async function startStellarDriver(o: DriverOptions, deps: StellarDriverDeps): Promise<ChainDriver> {
  if (!existsSync(STELLAR_REGISTRY_WASM)) throw new Error(`stellar registry wasm missing (${STELLAR_REGISTRY_WASM}); run: cd contracts/stellar && stellar contract build`);
  if (!(o.trustedRoot instanceof Uint8Array) || o.trustedRoot.length !== 64) throw new Error("stellar driver: trustedRoot must be 64 bytes");
  const node = await startStellarNode(o.rpcPort !== undefined ? { rpcPort: o.rpcPort } : {});
  try {
    const rpcUrl = node.rpcUrl;
    const sub = new StellarSubmitter(rpcUrl);
    const keys: Record<Signer, Keypair> = { owner: Keypair.random(), operator: Keypair.random(), operator2: Keypair.random(), stranger: Keypair.random() };
    // Friendbot needs a while after RPC is healthy (docs/stellar-local.md): the first funding waits for it.
    await fund(node, keys.owner.publicKey());
    await Promise.all((["operator", "operator2", "stranger"] as const).map((s) => fund(node, keys[s].publicKey(), 60_000)));

    const wasmHash = await sub.upload(keys.owner, new Uint8Array(readFileSync(STELLAR_REGISTRY_WASM)));
    const llm = await sub.deployRegistry(keys.owner, wasmHash, keys.owner.publicKey(), o.trustedRoot, o.instanceTtlMs);
    const vpn = await sub.deployRegistry(keys.owner, wasmHash, keys.owner.publicKey(), o.trustedRoot, o.instanceTtlMs);
    const contractOf = (reg: RegistryName) => (reg === "llm" ? llm : vpn);
    const reader = (c: string) => deps.reader({ rpcUrl, networkPassphrase: STELLAR_PASSPHRASE, contract: c });
    const registry = reader(llm);
    const vpnRegistry = reader(vpn);
    if (registry.contractId !== `stellar:${llm}` || vpnRegistry.contractId !== `stellar:${vpn}`) throw new Error("stellar driver: reader contractId mismatch");

    const signerKey = (signer: Signer): Keypair => {
      const k = keys[signer];
      if (!k) throw new Error(`unknown signer: ${String(signer)}`);
      return k;
    };
    const operatorId = (account: OperatorAccount): string => {
      if (!OPERATORS.includes(account)) throw new Error(`unknown operator account: ${String(account)}`);
      return keys[account].publicKey();
    };
    const hashArg = (method: string, h: unknown): xdr.ScVal => {
      if (typeof h !== "string" || !isHash32(h)) throw new Error(`${method} failed: hash must be 64 lowercase hex (non-zero)`);
      return scvBytesN(h);
    };
    const accountArg = (method: string, a: unknown): xdr.ScVal => {
      if (typeof a !== "string" || !StrKey.isValidEd25519PublicKey(a)) throw new Error(`${method} failed: account_id must be a G… strkey`);
      return new Address(a).toScVal();
    };
    let stopping = false;
    const invoke = async (reg: RegistryName, signer: Signer, method: string, args: xdr.ScVal[]): Promise<xdr.ScVal | undefined> => {
      if (stopping) throw new Error("stack is stopped");
      return sub.invoke(signerKey(signer), contractOf(reg), method, args);
    };

    const adminOf = new WeakMap<ChainAdmin, RegistryName>();
    const makeAdmin = (reg: RegistryName, signer: Signer): ChainAdmin => {
      const a: ChainAdmin = {
        allowCompose: async (h) => void (await invoke(reg, signer, "allow_compose", [hashArg("allow_compose", h)])),
        revokeCompose: async (h) => void (await invoke(reg, signer, "revoke_compose", [hashArg("revoke_compose", h)])),
        allowOs: async (h) => void (await invoke(reg, signer, "allow_os", [hashArg("allow_os", h)])),
        revokeOs: async (h) => void (await invoke(reg, signer, "revoke_os", [hashArg("revoke_os", h)])),
        approveOperator: async (account, orgId) =>
          void (await invoke(reg, signer, "approve_operator", [new Address(operatorId(account)).toScVal(), xdr.ScVal.scvString(orgId)])),
        revokeOperator: async (account) => void (await invoke(reg, signer, "revoke_operator", [new Address(operatorId(account)).toScVal()])),
      };
      adminOf.set(a, reg);
      return a;
    };

    /** NEAR-style owner method names/args (`S.call("owner", "revoke_compose", { hash })`). */
    const callOn = (reg: RegistryName): CallFn => async (signer, method, args) => {
      const a = args as Record<string, unknown>;
      switch (method) {
        case "allow_compose":
        case "revoke_compose":
        case "allow_os":
        case "revoke_os":
          await invoke(reg, signer, method, [hashArg(method, a.hash)]);
          return undefined;
        case "approve_operator":
          if (typeof a.org_id !== "string") throw new Error(`${method} failed: org_id must be a string`);
          await invoke(reg, signer, method, [accountArg(method, a.account_id), xdr.ScVal.scvString(a.org_id)]);
          return undefined;
        case "revoke_operator":
          await invoke(reg, signer, method, [accountArg(method, a.account_id)]);
          return undefined;
        default:
          throw new Error(`${method} failed: not an owner method of the Stellar registry driver`);
      }
    };

    const view = async <T>(method: string, args: object): Promise<T> => {
      const a = args as Record<string, unknown>;
      const r = registry as RegistryReader & { anchorCount?: () => Promise<number> };
      switch (method) {
        case "get_root":
          return (await registry.getRoot()) as T;
        case "is_compose_allowed":
          return (await registry.isComposeAllowed(String(a.hash))) as T;
        case "is_os_allowed":
          return (await registry.isOsAllowed(String(a.hash))) as T;
        case "get_instance":
          return (await registry.getInstance(String(a.key_hash))) as T;
        case "get_anchor":
          return (await registry.getAnchor(Number(a.id))) as T;
        case "anchor_count":
          if (typeof r.anchorCount !== "function") break;
          return (await r.anchorCount()) as T;
        case "contract_id": {
          const v = await sub.view(llm, "contract_id");
          return (v.type === "scvString" ? v.str.toString() : null) as T;
        }
        default:
          break;
      }
      throw new Error(`view: ${method} is not mapped by the Stellar driver (use stack.registry)`);
    };

    const stop = async (): Promise<void> => {
      stopping = true;
      await node.stop();
    };

    return {
      chain: "stellar",
      rpcUrl,
      contractId: registry.contractId,
      vpnContractId: vpnRegistry.contractId,
      registry,
      vpnRegistry,
      accounts: { owner: keys.owner.publicKey(), operator: keys.operator.publicKey(), operator2: keys.operator2.publicKey(), stranger: keys.stranger.publicKey() },
      admin: makeAdmin("llm", "owner"),
      vpnAdmin: makeAdmin("vpn", "owner"),
      asStranger: (a) => {
        const reg = adminOf.get(a);
        if (reg === undefined) throw new Error("asStranger: not an admin of this stack");
        return makeAdmin(reg, "stranger");
      },
      view,
      call: callOn("llm"),
      callVpn: callOn("vpn"),
      // The operator's own account key: router and exit share its sequence number (the writer retries txBadSeq).
      instanceEnv: async (op, registries) => ({
        PLR_CHAIN: "stellar",
        PLR_STELLAR_RPC: rpcUrl,
        PLR_STELLAR_PASSPHRASE: STELLAR_PASSPHRASE,
        ...(registries.includes("llm") ? { PLR_STELLAR_REGISTRY: llm } : {}),
        ...(registries.includes("vpn") ? { PLR_STELLAR_VPN_REGISTRY: vpn } : {}),
        PLR_STELLAR_KEY: keys[op === "operator2" ? "operator2" : "operator"].secret(),
      }),
      clientEnvLines: () => [
        "PLR_CHAIN=stellar",
        `PLR_STELLAR_RPC=${rpcUrl}`,
        `PLR_STELLAR_PASSPHRASE=${STELLAR_PASSPHRASE}`,
        `PLR_STELLAR_REGISTRY=${llm}`,
        `PLR_STELLAR_VPN_REGISTRY=${vpn}`,
        `PLR_REGISTRY=${registry.contractId}`,
        `PLR_VPN_REGISTRY=${vpnRegistry.contractId}`,
      ],
      ownerFile: () => ({
        chain: "stellar",
        rpc_url: rpcUrl,
        network_passphrase: STELLAR_PASSPHRASE,
        registry: llm,
        vpn_registry: vpn,
        owner: { account_id: keys.owner.publicKey(), secret_key: keys.owner.secret() },
      }),
      exportSigner: (signer) => {
        const k = signerKey(signer);
        return { accountId: k.publicKey(), secretKey: k.secret() };
      },
      stop,
    };
  } catch (e) {
    await node.stop();
    throw e;
  }
}

/** Hex of a contract's wasm hash (diagnostics). */
export const wasmHashHex = (wasm: Uint8Array): string => toHex(hash(wasm));

/** Contract args of an owner method with NEAR-style names/args (`stack-cli owner`). @throws Error on bad args */
export function stellarOwnerArgsOf(method: string, args: object): xdr.ScVal[] {
  const a = args as Record<string, unknown>;
  const hashArg = (): xdr.ScVal => {
    if (typeof a.hash !== "string" || !isHash32(a.hash)) throw new Error(`${method} failed: hash must be 64 lowercase hex (non-zero)`);
    return scvBytesN(a.hash);
  };
  const accountArg = (): xdr.ScVal => {
    if (typeof a.account_id !== "string" || !StrKey.isValidEd25519PublicKey(a.account_id)) throw new Error(`${method} failed: account_id must be a G… strkey`);
    return new Address(a.account_id).toScVal();
  };
  switch (method) {
    case "allow_compose":
    case "revoke_compose":
    case "allow_os":
    case "revoke_os":
      return [hashArg()];
    case "approve_operator":
      if (typeof a.org_id !== "string" || a.org_id.length > 64) throw new Error(`${method} failed: org_id must be a string`);
      return [accountArg(), xdr.ScVal.scvString(a.org_id)];
    case "revoke_operator":
      return [accountArg()];
    default:
      throw new Error(`${method} failed: not an owner method of the Stellar registry`);
  }
}

/** Posts one owner invocation signed by an `S…` secret and waits until it succeeded (`stack-cli owner`). */
export async function postStellarOwnerCall(
  p: { rpcUrl: string; networkPassphrase: string; registry: string; secretKey: string },
  method: string,
  args: object,
): Promise<{ signer: string }> {
  if (!StrKey.isValidContract(p.registry)) throw new Error(`${method} failed: registry must be a C… contract strkey`);
  if (!StrKey.isValidEd25519SecretSeed(p.secretKey)) throw new Error(`${method} failed: malformed owner key`);
  const kp = Keypair.fromSecret(p.secretKey);
  await new StellarSubmitter(p.rpcUrl, p.networkPassphrase).invoke(kp, p.registry, method, stellarOwnerArgsOf(method, args));
  return { signer: kp.publicKey() };
}
