/**
 * Solana chain driver (tier B, SPEC-CHAINS §6, §11; facts in docs/solana-local.md): one `solana-test-validator` per
 * stack, ledger under the stack's run dir, RPC on a free 127.0.0.1 port (websocket = port + 1), the registry program
 * (contracts/solana, `cargo-build-sbf` → target/deploy/plr_registry_solana.so) preloaded at a fresh program id with
 * `--bpf-program`.
 *
 * Boot: fresh ed25519 keys for the LLM registry owner, the VPN registry owner, operator, operator2 and stranger, each
 * airdropped from the validator's faucet; two registry state accounts (fresh keypairs) are created and `Init`ed in
 * one transaction each (owner, MOCK root = the stack's pinned root, the stack's instance TTL).
 *
 * Owner writes are program instructions signed by the owner key and resolve once confirmed (commitment `confirmed`,
 * the commitment the readers use). A stranger signs the same instructions with its own key as "owner": the program
 * refuses them (E_UNAUTHORIZED, the promise rejects).
 *
 * The registry reader is injected (`makeReader`, e.g. `(p) => new SolanaRegistry(p)` from `@plr/client`) so this file
 * does not depend on client exports.
 */
import { existsSync } from "node:fs";
import { mkdir } from "node:fs/promises";
import { homedir } from "node:os";
import { delimiter, dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { randomInt } from "node:crypto";
import { Connection, Keypair, PublicKey, SystemProgram, Transaction, TransactionInstruction, LAMPORTS_PER_SOL } from "@solana/web3.js";
import { isHash32, toHex, type RegistryReader } from "@plr/shared";
import { startManaged, waitFor, type ManagedProcess } from "../procs.js";
import { freePort } from "../sandbox.js";
import { OPERATORS, type CallFn, type ChainAdmin, type ChainDriver, type DriverOptions, type OperatorAccount, type RegistryName, type Signer } from "./driver.js";

const REPO_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..", "..", "..");
export const SOLANA_PROGRAM_SO = join(REPO_ROOT, "contracts", "solana", "target", "deploy", "plr_registry_solana.so");
const DEFAULT_SOLANA_BIN_DIR = join(homedir(), ".local", "share", "solana", "install", "active_release", "bin");

const STATE_LEN = 147;
const AIRDROP_SOL = 100;
const CONFIRM_TIMEOUT_MS = 60_000;
const READY_TIMEOUT_MS = 90_000;
const COMMITMENT = "confirmed" as const;
const ORG_RE = /^[a-z0-9][a-z0-9._-]{0,63}$/;

/** Instruction tags (SPEC-CHAINS §11). */
const IX = { INIT: 0, ALLOW_COMPOSE: 1, REVOKE_COMPOSE: 2, ALLOW_OS: 3, REVOKE_OS: 4, APPROVE_OPERATOR: 6, REVOKE_OPERATOR: 7 } as const;
/** `Custom(n)` names (SPEC-CHAINS §10 numbering). */
const ERRORS = ["E_UNAUTHORIZED", "E_ZERO_HASH", "E_BAD_INPUT", "E_OPERATOR_UNAPPROVED", "E_REPORT_DATA", "E_QUOTE_FORMAT", "E_SEQ", "E_INSTANCE_NOT_REGISTERED", "E_COMPOSE_NOT_ALLOWED"];

/** Reader factory (the harness passes `@plr/client`'s `SolanaRegistry`). */
export type SolanaReaderFactory = (p: { rpcUrl: string; programId: string; registry: string }) => RegistryReader;

/** Directory of the Agave tools: `SOLANA_BIN_DIR`, else the default install dir, else the PATH entry holding them; null if none. */
export function solanaBinDir(): string | null {
  const ok = (d: string) => existsSync(join(d, "solana-test-validator"));
  const fromEnv = process.env.SOLANA_BIN_DIR;
  if (fromEnv) return ok(fromEnv) ? fromEnv : null;
  if (ok(DEFAULT_SOLANA_BIN_DIR)) return DEFAULT_SOLANA_BIN_DIR;
  for (const d of (process.env.PATH ?? "").split(delimiter)) if (d && ok(d)) return d;
  return null;
}

const enc = new TextEncoder();
const sleep = (ms: number) => new Promise<void>((ok) => setTimeout(ok, ms));
const hexBytes = (h: string): Buffer => Buffer.from(h, "hex");

function u64le(n: number | bigint): Buffer {
  const b = Buffer.alloc(8);
  b.writeBigUInt64LE(BigInt(n));
  return b;
}

const pda = (programId: PublicKey, seed: string, state: PublicKey, x: Uint8Array): PublicKey =>
  PublicKey.findProgramAddressSync([enc.encode(seed), state.toBytes(), x], programId)[0];

/** Name of the program error in a failed send/confirm (`custom program error: 0x…` or `{Custom: n}`), or null. */
export function programErrorName(e: unknown): string | null {
  const s = e instanceof Error ? `${e.message} ${JSON.stringify((e as { logs?: unknown }).logs ?? "")}` : JSON.stringify(e);
  const hex = /custom program error: 0x([0-9a-f]+)/i.exec(s);
  const dec = /"Custom":\s*(\d+)/.exec(s);
  const n = hex ? Number.parseInt(hex[1]!, 16) : dec ? Number(dec[1]) : NaN;
  return Number.isInteger(n) && n >= 1 && n <= ERRORS.length ? ERRORS[n - 1]! : null;
}

/** Signs, sends (with preflight: program errors reject with their logs) and polls until confirmed (bounded). */
export async function sendAndConfirm(conn: Connection, ixs: TransactionInstruction[], signers: Keypair[], timeoutMs = CONFIRM_TIMEOUT_MS): Promise<string> {
  const bh = await conn.getLatestBlockhash(COMMITMENT);
  const tx = new Transaction({ feePayer: signers[0]!.publicKey, blockhash: bh.blockhash, lastValidBlockHeight: bh.lastValidBlockHeight }).add(...ixs);
  tx.sign(...signers);
  const raw = tx.serialize();
  let sig: string;
  try {
    sig = await conn.sendRawTransaction(raw, { preflightCommitment: COMMITMENT, maxRetries: 0 });
  } catch (e) {
    const name = programErrorName(e);
    throw new Error(name ? `solana transaction refused: ${name}` : `solana transaction failed: ${e instanceof Error ? e.message.slice(0, 300) : String(e)}`);
  }
  const deadline = Date.now() + timeoutMs;
  let lastSend = Date.now();
  for (;;) {
    await sleep(300);
    const st = (await conn.getSignatureStatuses([sig]).catch(() => null))?.value[0];
    if (st && (st.confirmationStatus === "confirmed" || st.confirmationStatus === "finalized")) {
      if (st.err !== null) {
        const name = programErrorName(st.err);
        throw new Error(name ? `solana transaction refused: ${name}` : `solana transaction failed: ${JSON.stringify(st.err)}`);
      }
      return sig;
    }
    if (Date.now() >= deadline) throw new Error(`solana transaction ${sig.slice(0, 16)}… not confirmed in time`);
    if (Date.now() - lastSend > 2000) {
      lastSend = Date.now();
      await conn.sendRawTransaction(raw, { skipPreflight: true, maxRetries: 0 }).catch(() => undefined);
    }
  }
}

/** Instruction builders for the owner methods of one registry. */
export class SolanaOwnerIx {
  constructor(readonly programId: PublicKey, readonly state: PublicKey) {}
  #ix(keys: { pubkey: PublicKey; isSigner: boolean; isWritable: boolean }[], data: Buffer): TransactionInstruction {
    return new TransactionInstruction({ programId: this.programId, keys, data });
  }
  init(owner: PublicKey, rootP256: Uint8Array, ttlMs: number): TransactionInstruction {
    if (rootP256.length !== 64) throw new Error("solana init: root must be 64 bytes");
    return this.#ix([{ pubkey: this.state, isSigner: true, isWritable: true }], Buffer.concat([Buffer.of(IX.INIT), owner.toBuffer(), Buffer.of(1), Buffer.from(rootP256), u64le(ttlMs)]));
  }
  /** allow/revoke compose/os (`h` 64 lowercase hex). */
  item(kind: "allow_compose" | "revoke_compose" | "allow_os" | "revoke_os", signer: PublicKey, h: string): TransactionInstruction {
    if (!/^[0-9a-f]{64}$/.test(h)) throw new Error(`${kind} failed: hash must be 64 lowercase hex`);
    const tag = { allow_compose: IX.ALLOW_COMPOSE, revoke_compose: IX.REVOKE_COMPOSE, allow_os: IX.ALLOW_OS, revoke_os: IX.REVOKE_OS }[kind];
    const seed = kind.endsWith("compose") ? "compose" : "os";
    return this.#ix(
      [
        { pubkey: this.state, isSigner: false, isWritable: false },
        { pubkey: signer, isSigner: true, isWritable: true },
        { pubkey: pda(this.programId, seed, this.state, hexBytes(h)), isSigner: false, isWritable: true },
        { pubkey: SystemProgram.programId, isSigner: false, isWritable: false },
      ],
      Buffer.concat([Buffer.of(tag), hexBytes(h)]),
    );
  }
  approveOperator(signer: PublicKey, op: PublicKey, orgId: string): TransactionInstruction {
    const org = Buffer.from(orgId, "utf8");
    if (org.length > 255) throw new Error("approve_operator failed: org_id too long");
    return this.#ix(
      [
        { pubkey: this.state, isSigner: false, isWritable: false },
        { pubkey: signer, isSigner: true, isWritable: true },
        { pubkey: pda(this.programId, "op", this.state, op.toBytes()), isSigner: false, isWritable: true },
        { pubkey: SystemProgram.programId, isSigner: false, isWritable: false },
      ],
      Buffer.concat([Buffer.of(IX.APPROVE_OPERATOR), op.toBuffer(), Buffer.of(org.length), org]),
    );
  }
  revokeOperator(signer: PublicKey, op: PublicKey): TransactionInstruction {
    return this.#ix(
      [
        { pubkey: this.state, isSigner: false, isWritable: false },
        { pubkey: signer, isSigner: true, isWritable: true },
        { pubkey: pda(this.programId, "op", this.state, op.toBytes()), isSigner: false, isWritable: true },
      ],
      Buffer.concat([Buffer.of(IX.REVOKE_OPERATOR), op.toBuffer()]),
    );
  }
}

/** A dynamic port range for this validator's internal ports, picked at random (stacks may run side by side). */
function portRange(): string {
  const base = 20_000 + randomInt(0, 400) * 100;
  return `${base}-${base + 100}`;
}

/** Two consecutive free ports (RPC + websocket). */
async function freePortPair(): Promise<number> {
  for (let i = 0; i < 50; i++) {
    const p = await freePort();
    if (p >= 65535) continue;
    const net = await import("node:net");
    const free = await new Promise<boolean>((ok) => {
      const s = net.createServer();
      s.once("error", () => ok(false));
      s.listen(p + 1, "127.0.0.1", () => s.close(() => ok(true)));
    });
    if (free) return p;
  }
  throw new Error("no free port pair for the Solana RPC");
}

export async function startSolanaDriver(o: DriverOptions, makeReader: SolanaReaderFactory): Promise<ChainDriver> {
  const binDir = solanaBinDir();
  if (binDir === null) throw new Error("solana-test-validator not found (install Agave, or set SOLANA_BIN_DIR)");
  if (!existsSync(SOLANA_PROGRAM_SO)) throw new Error(`registry program missing (${SOLANA_PROGRAM_SO}); run: cd contracts/solana && cargo-build-sbf`);
  if (typeof makeReader !== "function") throw new Error("startSolanaDriver: makeReader required");
  const dir = join(o.dir, "solana");
  const ledger = join(dir, "ledger");
  await mkdir(ledger, { recursive: true, mode: 0o700 });
  const rpcPort = o.rpcPort ?? (await freePortPair());
  const faucetPort = await freePort();
  const gossipPort = await freePort();
  const rpcUrl = `http://127.0.0.1:${rpcPort}`;
  const programKp = Keypair.generate();
  const programId = programKp.publicKey;

  const proc: ManagedProcess = startManaged({
    name: "solana-test-validator",
    cmd: join(binDir, "solana-test-validator"),
    args: [
      "--ledger", ledger,
      "--reset",
      "--quiet",
      "--bind-address", "127.0.0.1",
      "--rpc-port", String(rpcPort),
      "--faucet-port", String(faucetPort),
      "--gossip-port", String(gossipPort),
      "--dynamic-port-range", portRange(),
      "--bpf-program", programId.toBase58(), SOLANA_PROGRAM_SO,
    ],
    env: { PATH: `${binDir}${delimiter}${process.env.PATH ?? "/usr/bin:/bin"}`, HOME: dir },
    maxOutput: 256 * 1024,
    graceMs: 5000,
  });
  let stopped: Promise<void> | null = null;
  const stop = (): Promise<void> =>
    (stopped ??= (async () => {
      await proc.stop();
    })());

  try {
    const conn = new Connection(rpcUrl, { commitment: COMMITMENT, disableRetryOnRateLimit: true });
    await waitFor("solana-test-validator RPC", async () => {
      if (proc.exited) throw new Error(`solana-test-validator exited early:\n${proc.output().slice(-4000)}`);
      const slot = await conn.getSlot(COMMITMENT).catch(() => -1);
      if (slot < 1) return undefined;
      const prog = await conn.getAccountInfo(programId, COMMITMENT).catch(() => null);
      return prog?.executable ? (true as const) : undefined;
    }, READY_TIMEOUT_MS, 250);

    const keys = {
      owner: Keypair.generate(),
      vpnOwner: Keypair.generate(),
      operator: Keypair.generate(),
      operator2: Keypair.generate(),
      stranger: Keypair.generate(),
    };
    const airdrops = await Promise.all(Object.values(keys).map((k) => conn.requestAirdrop(k.publicKey, AIRDROP_SOL * LAMPORTS_PER_SOL)));
    await waitFor("solana airdrops", async () => {
      const st = await conn.getSignatureStatuses(airdrops).catch(() => null);
      return st && st.value.every((s) => s && s.err === null && (s.confirmationStatus === "confirmed" || s.confirmationStatus === "finalized")) ? (true as const) : undefined;
    }, CONFIRM_TIMEOUT_MS, 250);

    // The two registries: one state account each, created and initialized atomically by its owner.
    const rent = await conn.getMinimumBalanceForRentExemption(STATE_LEN, COMMITMENT);
    const createRegistry = async (owner: Keypair): Promise<{ state: PublicKey; ix: SolanaOwnerIx }> => {
      const stateKp = Keypair.generate();
      const ix = new SolanaOwnerIx(programId, stateKp.publicKey);
      await sendAndConfirm(conn, [
        SystemProgram.createAccount({ fromPubkey: owner.publicKey, newAccountPubkey: stateKp.publicKey, lamports: rent, space: STATE_LEN, programId }),
        ix.init(owner.publicKey, o.trustedRoot, o.instanceTtlMs),
      ], [owner, stateKp]);
      return { state: stateKp.publicKey, ix };
    };
    const llm = await createRegistry(keys.owner);
    const vpn = await createRegistry(keys.vpnOwner);
    const regs: Record<RegistryName, { state: PublicKey; ix: SolanaOwnerIx }> = { llm, vpn };

    const readerOf = (state: PublicKey) => makeReader({ rpcUrl, programId: programId.toBase58(), registry: state.toBase58() });
    const registry = readerOf(llm.state);
    const vpnRegistry = readerOf(vpn.state);

    const keyOf = (reg: RegistryName, signer: Signer): Keypair => {
      if (signer === "owner") return reg === "llm" ? keys.owner : keys.vpnOwner;
      if (signer !== "operator" && signer !== "operator2" && signer !== "stranger") throw new Error(`unknown signer: ${String(signer)}`);
      return keys[signer];
    };
    const operatorKey = (account: OperatorAccount): Keypair => {
      if (!OPERATORS.includes(account)) throw new Error(`unknown operator account: ${String(account)}`);
      return keys[account];
    };
    const send = async (kp: Keypair, ix: TransactionInstruction): Promise<void> => {
      if (stopped) throw new Error("stack is stopped");
      await sendAndConfirm(conn, [ix], [kp]);
    };
    const checkOrg = (orgId: string): string => {
      if (typeof orgId !== "string" || !ORG_RE.test(orgId)) throw new Error("approve_operator failed: E_BAD_INPUT (org_id)");
      return orgId;
    };

    const adminOf = new WeakMap<ChainAdmin, RegistryName>();
    const makeAdmin = (reg: RegistryName, signer: Signer): ChainAdmin => {
      const kp = keyOf(reg, signer);
      const b = regs[reg].ix;
      const a: ChainAdmin = {
        allowCompose: (h) => send(kp, b.item("allow_compose", kp.publicKey, h)),
        revokeCompose: (h) => send(kp, b.item("revoke_compose", kp.publicKey, h)),
        allowOs: (h) => send(kp, b.item("allow_os", kp.publicKey, h)),
        revokeOs: (h) => send(kp, b.item("revoke_os", kp.publicKey, h)),
        approveOperator: (account, orgId) => send(kp, b.approveOperator(kp.publicKey, operatorKey(account).publicKey, checkOrg(orgId))),
        revokeOperator: (account) => send(kp, b.revokeOperator(kp.publicKey, operatorKey(account).publicKey)),
      };
      adminOf.set(a, reg);
      return a;
    };

    /** NEAR-style owner method names (`stack-cli owner`, `S.call`); `account_id` is a base58 address. */
    const callOn = (reg: RegistryName): CallFn => async (signer, method, args) => {
      const kp = keyOf(reg, signer);
      const b = regs[reg].ix;
      const x = args as Record<string, unknown>;
      const acct = (): PublicKey => {
        const s = x.account_id;
        try {
          if (typeof s === "string") return new PublicKey(s);
        } catch {
          // fall through
        }
        throw new Error(`${method} failed: account_id must be a base58 address`);
      };
      const hash = (): string => {
        if (typeof x.hash !== "string" || !isHash32(x.hash)) throw new Error(`${method} failed: hash must be 64 lowercase hex`);
        return x.hash;
      };
      let ix: TransactionInstruction;
      switch (method) {
        case "allow_compose":
        case "revoke_compose":
        case "allow_os":
        case "revoke_os":
          ix = b.item(method, kp.publicKey, hash());
          break;
        case "approve_operator":
          if (typeof x.org_id !== "string") throw new Error(`${method} failed: org_id must be a string`);
          ix = b.approveOperator(kp.publicKey, acct(), x.org_id);
          break;
        case "revoke_operator":
          ix = b.revokeOperator(kp.publicKey, acct());
          break;
        default:
          throw new Error(`${method} failed: not an owner method of the Solana registry`);
      }
      try {
        await send(kp, ix);
      } catch (e) {
        const msg = e instanceof Error ? e.message : String(e);
        throw new Error(`${method} failed: ${msg}`);
      }
      return undefined;
    };

    const view = async <T>(method: string, args: object): Promise<T> => {
      const x = args as Record<string, unknown>;
      const r = registry as RegistryReader & { getOperator?: (a: string) => Promise<string | null> };
      switch (method) {
        case "get_root":
          return (await r.getRoot()) as T;
        case "is_compose_allowed":
          return (await r.isComposeAllowed(String(x.hash))) as T;
        case "is_os_allowed":
          return (await r.isOsAllowed(String(x.hash))) as T;
        case "get_instance":
          return (await r.getInstance(String(x.key_hash))) as T;
        case "get_anchor":
          return (await r.getAnchor(Number(x.id))) as T;
        case "get_operator":
          if (!r.getOperator) throw new Error("view get_operator: reader has no getOperator");
          return (await r.getOperator(String(x.account_id))) as T;
        default:
          throw new Error(`view ${method}: not a view of the Solana registry (use stack.registry)`);
      }
    };

    const secretHex = (k: Keypair) => toHex(k.secretKey);
    return {
      chain: "solana",
      rpcUrl,
      contractId: registry.contractId,
      vpnContractId: vpnRegistry.contractId,
      registry,
      vpnRegistry,
      accounts: {
        owner: keys.owner.publicKey.toBase58(),
        operator: keys.operator.publicKey.toBase58(),
        operator2: keys.operator2.publicKey.toBase58(),
        stranger: keys.stranger.publicKey.toBase58(),
      },
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
      instanceEnv: async (op, registries) => ({
        PLR_CHAIN: "solana",
        PLR_SOLANA_RPC: rpcUrl,
        PLR_SOLANA_PROGRAM: programId.toBase58(),
        ...(registries.includes("llm") ? { PLR_SOLANA_REGISTRY: llm.state.toBase58() } : {}),
        ...(registries.includes("vpn") ? { PLR_SOLANA_VPN_REGISTRY: vpn.state.toBase58() } : {}),
        PLR_SOLANA_KEY: secretHex(operatorKey(op)),
      }),
      clientEnvLines: () => [
        "PLR_CHAIN=solana",
        `PLR_SOLANA_RPC=${rpcUrl}`,
        `PLR_SOLANA_PROGRAM=${programId.toBase58()}`,
        `PLR_SOLANA_REGISTRY=${llm.state.toBase58()}`,
        `PLR_SOLANA_VPN_REGISTRY=${vpn.state.toBase58()}`,
        `PLR_REGISTRY=${registry.contractId}`,
        `PLR_VPN_REGISTRY=${vpnRegistry.contractId}`,
      ],
      ownerFile: () => ({
        chain: "solana",
        rpc_url: rpcUrl,
        program_id: programId.toBase58(),
        registry: llm.state.toBase58(),
        vpn_registry: vpn.state.toBase58(),
        owner: { address: keys.owner.publicKey.toBase58(), secret_key: secretHex(keys.owner) },
        vpn_owner: { address: keys.vpnOwner.publicKey.toBase58(), secret_key: secretHex(keys.vpnOwner) },
      }),
      exportSigner: (signer) => {
        const k = keyOf("llm", signer);
        return { accountId: k.publicKey.toBase58(), secretKey: secretHex(k) };
      },
      stop,
    };
  } catch (e) {
    await stop();
    throw e;
  }
}

/** Posts one owner instruction with a 64-byte hex secret and waits until confirmed (`stack-cli owner`). */
export async function postSolanaOwnerCall(
  p: { rpcUrl: string; programId: string; registry: string; secretKey: string },
  method: string,
  args: object,
): Promise<{ signature: string; signer: string }> {
  const kp = Keypair.fromSecretKey(Uint8Array.from(Buffer.from(p.secretKey, "hex")));
  const conn = new Connection(p.rpcUrl, { commitment: COMMITMENT, disableRetryOnRateLimit: true });
  const b = new SolanaOwnerIx(new PublicKey(p.programId), new PublicKey(p.registry));
  const x = args as Record<string, unknown>;
  let ix: TransactionInstruction;
  if (method === "allow_compose" || method === "revoke_compose" || method === "allow_os" || method === "revoke_os") {
    ix = b.item(method, kp.publicKey, String(x.hash));
  } else if (method === "approve_operator") {
    ix = b.approveOperator(kp.publicKey, new PublicKey(String(x.account_id)), String(x.org_id));
  } else if (method === "revoke_operator") {
    ix = b.revokeOperator(kp.publicKey, new PublicKey(String(x.account_id)));
  } else {
    throw new Error(`${method} failed: not an owner method of the Solana registry`);
  }
  return { signature: await sendAndConfirm(conn, [ix], [kp]), signer: kp.publicKey.toBase58() };
}
