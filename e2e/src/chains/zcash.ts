/**
 * Zcash chain driver (tier C, SPEC-CHAINS §5, §6, §8): one `zebrad` regtest node per stack, state under the stack's
 * run dir (ephemeral), RPC on a free 127.0.0.1 port.
 *
 * Boot: fresh secp256k1 keys for the faucet (the node's `miner_address`), the LLM registry owner, the VPN registry
 * owner (two registries = two owner addresses), operator, operator2 and stranger; the node mines 110 blocks (coinbase
 * maturity is 100), then each account gets its own matured coinbase split into 40 P2PKH coins (operator: 80, it runs
 * every router and exit), so writers can submit several records without waiting for change. A background miner then
 * calls `generate 1` every second while the stack runs. Both owners post `set_root` (MOCK, the stack's pinned root).
 *
 * Owner writes are OP_RETURN records (`"PLR1" ‖ type ‖ body`) in v5 transparent transactions built and signed here
 * (ZIP-244 sighash, ZIP-317 fee) and resolve once mined. A stranger's records are simply not policy: readers ignore them.
 */
import { existsSync } from "node:fs";
import { mkdir, writeFile } from "node:fs/promises";
import { homedir } from "node:os";
import { delimiter, join } from "node:path";
import { secp256k1 } from "@noble/curves/secp256k1.js";
import {
  buildSignedTransparentTx, encodeZcashRecord, hash160, isHash32, opReturnScript, p2pkhScript, parseTAddress, parseZcashSecretKey,
  tAddress, toHex, zcashTxid, zcashTxidFromRpc, zcashTxidToRpc, zip317Fee, type ZcashNetwork, type ZcashRecord,
} from "@plr/shared";
import { ZcashRegistry } from "@plr/client";
import { startManaged, waitFor, type ManagedProcess } from "../procs.js";
import { freePort } from "../sandbox.js";
import { OPERATORS, type CallFn, type ChainAdmin, type ChainDriver, type DriverOptions, type OperatorAccount, type RegistryName, type Signer } from "./driver.js";

const NETWORK: ZcashNetwork = "regtest";
/** Blocks mined before funding: coinbase outputs are spendable after 100 confirmations (SPEC-CHAINS §8). */
const INITIAL_BLOCKS = 110;
const COINS_PER_COINBASE = 40;
const MINER_PERIOD_MS = 1000;
const CONFIRM_TIMEOUT_MS = 90_000;
const RPC_TIMEOUT_MS = 15_000;
/** Transaction expiry = tip + this. */
const EXPIRY_DELTA = 40;
/** Coins below fee + this are not spent (change never becomes dust). */
const MIN_CHANGE = 10_000n;
const MAX_SUBMIT_ATTEMPTS = 6;
const TXID_RE = /^[0-9a-f]{64}$/;

const sleep = (ms: number) => new Promise<void>((ok) => setTimeout(ok, ms));
const isObj = (v: unknown): v is Record<string, unknown> => typeof v === "object" && v !== null && !Array.isArray(v);
const isUint = (n: unknown): n is number => typeof n === "number" && Number.isSafeInteger(n) && n >= 0;

/** `zebrad` to use: `ZEBRAD_BIN`, else `~/.cargo/bin/zebrad`, else the first `zebrad` on PATH; null if none. */
export function zebradBinary(): string | null {
  const fromEnv = process.env.ZEBRAD_BIN;
  if (fromEnv) return existsSync(fromEnv) ? fromEnv : null;
  const cargo = join(homedir(), ".cargo", "bin", "zebrad");
  if (existsSync(cargo)) return cargo;
  for (const d of (process.env.PATH ?? "").split(delimiter)) {
    if (d && existsSync(join(d, "zebrad"))) return join(d, "zebrad");
  }
  return null;
}

// ------------------------------------------------------------------------------------------------ JSON-RPC

/** Minimal Zebra JSON-RPC client (harness side: errors carry the node's message for diagnostics). */
export class ZebraClient {
  #id = 0;
  constructor(readonly url: string) {}
  async call(method: string, params: unknown[] = [], timeoutMs = RPC_TIMEOUT_MS): Promise<unknown> {
    const res = await fetch(this.url, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ jsonrpc: "2.0", id: ++this.#id, method, params }),
      signal: AbortSignal.timeout(timeoutMs),
    });
    const text = await res.text();
    let body: unknown;
    try {
      body = JSON.parse(text);
    } catch {
      throw new Error(`zebra ${method}: HTTP ${res.status} ${text.slice(0, 200)}`);
    }
    if (!isObj(body)) throw new Error(`zebra ${method}: bad response`);
    if (body.error !== undefined && body.error !== null) throw new Error(`zebra ${method}: ${JSON.stringify(body.error).slice(0, 400)}`);
    return body.result;
  }
  async tip(): Promise<number> {
    const n = await this.call("getblockcount");
    if (!isUint(n)) throw new Error("zebra getblockcount: bad result");
    return n;
  }
  async branchId(): Promise<number> {
    const info = await this.call("getblockchaininfo");
    const nb = isObj(info) && isObj(info.consensus) ? info.consensus.nextblock : undefined;
    if (typeof nb !== "string" || !/^[0-9a-f]{8}$/.test(nb) || Number.parseInt(nb, 16) === 0) throw new Error("zebra getblockchaininfo: no consensus.nextblock");
    return Number.parseInt(nb, 16);
  }
  /** Block height of a mined transaction, or null (mempool / unknown). */
  async minedHeight(txid: string): Promise<number | null> {
    try {
      const t = await this.call("getrawtransaction", [txid, 1]);
      return isObj(t) && isUint(t.height) && t.height > 0 ? t.height : null;
    } catch {
      return null;
    }
  }
}

// ------------------------------------------------------------------------------------------------ keys & records

interface Coin {
  txid: string;
  vout: number;
  amount: bigint;
  height: number;
}

/** One t-address with its own coins; posts OP_RETURN records signed by its key. */
export class ZcashKeyWriter {
  readonly secretKey: Uint8Array;
  readonly hash160: Uint8Array;
  readonly address: string;
  readonly #script: Uint8Array;
  readonly #scriptHex: string;
  /** outpoint → expiry height of our pending transaction spending it */
  readonly #reserved = new Map<string, number>();

  constructor(readonly rpc: ZebraClient, secretKey: Uint8Array, readonly network: ZcashNetwork = NETWORK) {
    if (secretKey.length !== 32 || !secp256k1.utils.isValidSecretKey(secretKey)) throw new Error("zcash: bad secret key");
    this.secretKey = secretKey.slice();
    this.hash160 = hash160(secp256k1.getPublicKey(this.secretKey, true));
    this.address = tAddress(this.hash160, network);
    this.#script = p2pkhScript(this.hash160);
    this.#scriptHex = toHex(this.#script);
  }

  static random(rpc: ZebraClient): ZcashKeyWriter {
    return new ZcashKeyWriter(rpc, secp256k1.utils.randomSecretKey());
  }

  /** Confirmed P2PKH coins of this address (`getaddressutxos`), coinbase ones only if matured. Drops stale reservations. */
  async coins(tip: number): Promise<Coin[]> {
    const r = await this.rpc.call("getaddressutxos", [{ addresses: [this.address] }]);
    if (!Array.isArray(r)) throw new Error("zebra getaddressutxos: bad result");
    const out: Coin[] = [];
    for (const u of r as unknown[]) {
      if (!isObj(u) || typeof u.txid !== "string" || !TXID_RE.test(u.txid) || !isUint(u.outputIndex) || u.script !== this.#scriptHex) continue;
      if (!isUint(u.satoshis) || !isUint(u.height) || u.height === 0) continue;
      out.push({ txid: u.txid, vout: u.outputIndex, amount: BigInt(u.satoshis), height: u.height });
    }
    const present = new Set(out.map((c) => `${c.txid}:${c.vout}`));
    for (const [k, exp] of this.#reserved) if (!present.has(k) || tip > exp) this.#reserved.delete(k);
    return out;
  }

  /**
   * Builds, signs and submits one transaction spending one of our coins: `outputs` + change back to us (if any).
   * Retries with another coin when the node rejects it. Returns the RPC txid.
   */
  async send(outputs: { amount: bigint; script: Uint8Array }[], o: { change: boolean; coin?: Coin } = { change: true }): Promise<string> {
    const outScripts = outputs.map((x) => x.script);
    const fee = zip317Fee({ inputs: 1, outputScripts: o.change ? [...outScripts, this.#script] : outScripts });
    const spend = outputs.reduce((s, x) => s + x.amount, 0n);
    let last: unknown = null;
    for (let attempt = 0; attempt < MAX_SUBMIT_ATTEMPTS; attempt++) {
      const tip = await this.rpc.tip();
      let coin = o.coin;
      if (coin === undefined) {
        const ok = (await this.coins(tip)).filter((c) => c.amount >= spend + fee + MIN_CHANGE && !this.#reserved.has(`${c.txid}:${c.vout}`));
        if (ok.length === 0) throw new Error(`zcash ${this.address}: no spendable coin`);
        coin = ok[Math.floor(Math.random() * ok.length)]!;
      }
      const expiryHeight = tip + EXPIRY_DELTA;
      const raw = buildSignedTransparentTx({
        branchId: await this.rpc.branchId(),
        expiryHeight,
        inputs: [{ txid: zcashTxidFromRpc(coin.txid), vout: coin.vout, amount: coin.amount, secretKey: this.secretKey }],
        outputs: o.change ? [...outputs, { amount: coin.amount - spend - fee, script: this.#script }] : outputs,
      });
      const txid = zcashTxidToRpc(zcashTxid(raw));
      this.#reserved.set(`${coin.txid}:${coin.vout}`, expiryHeight);
      try {
        const r = await this.rpc.call("sendrawtransaction", [toHex(raw)]);
        if (r !== txid) throw new Error(`sendrawtransaction: txid mismatch (${String(r)} ≠ ${txid})`);
        return txid;
      } catch (e) {
        last = e;
        if (o.coin !== undefined) break;
      }
    }
    throw last instanceof Error ? last : new Error("sendrawtransaction failed");
  }

  /** Submits one record (an OP_RETURN output + change). */
  post(r: ZcashRecord): Promise<string> {
    return this.send([{ amount: 0n, script: opReturnScript(encodeZcashRecord(r)) }]);
  }
}

/** Waits (bounded) until every transaction is mined; returns the highest block height. */
export async function waitMined(rpc: ZebraClient, txids: string[], timeoutMs = CONFIRM_TIMEOUT_MS): Promise<number> {
  let max = 0;
  for (const txid of txids) {
    const h = await waitFor(`zcash tx ${txid.slice(0, 16)}… to be mined`, () => rpc.minedHeight(txid).then((x) => x ?? undefined), timeoutMs, 250);
    max = Math.max(max, h);
  }
  return max;
}

/** The owner record of a NEAR-style owner method (`stack-cli owner`, `call`): `account_id` is a t-address. */
export function ownerRecordOf(method: string, args: object): ZcashRecord {
  const o = args as Record<string, unknown>;
  const hash = (): string => {
    if (typeof o.hash !== "string" || !isHash32(o.hash)) throw new Error(`${method} failed: hash must be 64 lowercase hex`);
    return o.hash;
  };
  const h160 = (): string => {
    if (typeof o.account_id !== "string") throw new Error(`${method} failed: account_id must be a t-address`);
    try {
      return toHex(parseTAddress(o.account_id).hash160);
    } catch {
      throw new Error(`${method} failed: account_id must be a P2PKH t-address`);
    }
  };
  switch (method) {
    case "allow_compose":
    case "revoke_compose":
    case "allow_os":
    case "revoke_os":
      return { type: method, hash: hash() };
    case "approve_operator":
      if (typeof o.org_id !== "string") throw new Error(`${method} failed: org_id must be a string`);
      return { type: "approve_operator", hash160: h160(), org_id: o.org_id };
    case "revoke_operator":
      return { type: "revoke_operator", hash160: h160() };
    default:
      throw new Error(`${method} failed: not an owner method of the Zcash registry`);
  }
}

/** Posts one owner record with `secretKey` and waits until it is mined (`stack-cli owner`). */
export async function postOwnerRecord(rpcUrl: string, secretKey: string, method: string, args: object): Promise<{ txid: string; height: number; signer: string }> {
  const rpc = new ZebraClient(rpcUrl);
  const w = new ZcashKeyWriter(rpc, parseZcashSecretKey(secretKey));
  const txid = await w.post(ownerRecordOf(method, args));
  const height = await waitMined(rpc, [txid]);
  return { txid, height, signer: w.address };
}

// ------------------------------------------------------------------------------------------------ driver

function zebradConfig(o: { minerAddress: string; rpcPort: number; stateDir: string }): string {
  return [
    "[network]",
    'network = "Regtest"',
    'listen_addr = "127.0.0.1:0"',
    "cache_dir = false",
    "[network.testnet_parameters.activation_heights]",
    "Canopy = 1",
    "NU5 = 1",
    "NU6 = 1",
    '"NU6.1" = 1',
    "[mining]",
    `miner_address = "${o.minerAddress}"`,
    "[state]",
    "ephemeral = true",
    `cache_dir = ${JSON.stringify(o.stateDir)}`,
    "[rpc]",
    `listen_addr = "127.0.0.1:${o.rpcPort}"`,
    "enable_cookie_auth = false",
    "[tracing]",
    'filter = "warn"',
    "",
  ].join("\n");
}

export async function startZcashDriver(o: DriverOptions): Promise<ChainDriver> {
  const bin = zebradBinary();
  if (bin === null) throw new Error("zebrad not found (install it with `cargo install zebrad`, or set ZEBRAD_BIN)");
  const dir = join(o.dir, "zcash");
  const stateDir = join(dir, "state");
  await mkdir(stateDir, { recursive: true, mode: 0o700 });
  const rpcPort = o.rpcPort ?? (await freePort());
  const rpcUrl = `http://127.0.0.1:${rpcPort}`;
  const rpc = new ZebraClient(rpcUrl);

  const faucet = ZcashKeyWriter.random(rpc);
  const keys = {
    owner: ZcashKeyWriter.random(rpc),
    vpnOwner: ZcashKeyWriter.random(rpc),
    operator: ZcashKeyWriter.random(rpc),
    operator2: ZcashKeyWriter.random(rpc),
    stranger: ZcashKeyWriter.random(rpc),
  };
  const cfgPath = join(dir, "zebrad.toml");
  await writeFile(cfgPath, zebradConfig({ minerAddress: faucet.address, rpcPort, stateDir }), { mode: 0o600 });

  const proc: ManagedProcess = startManaged({
    name: "zebrad",
    cmd: bin,
    args: ["-c", cfgPath, "start"],
    // `ephemeral = true` puts the database in a fresh directory under TMPDIR (not `cache_dir`): keep it in the run dir.
    env: { PATH: process.env.PATH ?? "/usr/bin:/bin", HOME: dir, TMPDIR: stateDir },
    maxOutput: 256 * 1024,
    graceMs: 5000,
  });
  let minerStop = false;
  let miner: Promise<void> | null = null;
  let stopped: Promise<void> | null = null;
  const stop = (): Promise<void> =>
    (stopped ??= (async () => {
      minerStop = true;
      await miner?.catch(() => undefined);
      await proc.stop();
    })());
  try {
    await waitFor("zebrad RPC", async () => {
      if (proc.exited) throw new Error(`zebrad exited early:\n${proc.output().slice(-4000)}`);
      return rpc.tip().then(() => true as const, () => undefined);
    }, 60_000, 250);
    // The block template may not be ready right after start: retry `generate` until it works (bounded).
    await waitFor("zebrad initial blocks", async () => {
      if (proc.exited) throw new Error(`zebrad exited:\n${proc.output().slice(-4000)}`);
      const tip = await rpc.tip().catch(() => -1);
      if (tip >= INITIAL_BLOCKS) return true as const;
      await rpc.call("generate", [INITIAL_BLOCKS - Math.max(tip, 0)], 120_000).catch(() => undefined);
      return undefined;
    }, 180_000, 500);

    // Funding: one matured coinbase per (account, share), split into COINS_PER_COINBASE coins without change.
    const shares: ZcashKeyWriter[] = [keys.owner, keys.vpnOwner, keys.operator, keys.operator, keys.operator2, keys.stranger];
    const tip0 = await rpc.tip();
    // Coinbase outputs are spendable in block tip + 1 once 100 blocks deep.
    const coinbases = (await faucet.coins(tip0)).filter((c) => c.height + 100 <= tip0).sort((a, b) => a.height - b.height);
    if (coinbases.length < shares.length) throw new Error(`zcash faucet: only ${coinbases.length} matured coinbase outputs`);
    const fundTxids: string[] = [];
    for (const [i, k] of shares.entries()) {
      const cb = coinbases[i]!;
      const script = p2pkhScript(k.hash160);
      const fee = zip317Fee({ inputs: 1, outputScripts: Array.from({ length: COINS_PER_COINBASE }, () => script) });
      const each = (cb.amount - fee) / BigInt(COINS_PER_COINBASE);
      if (each < 1_000_000n) throw new Error("zcash faucet: coinbase too small");
      fundTxids.push(await faucet.send(Array.from({ length: COINS_PER_COINBASE }, () => ({ amount: each, script })), { change: false, coin: cb }));
    }

    // The background miner: one block per second while the stack runs.
    miner = (async () => {
      while (!minerStop) {
        await rpc.call("generate", [1], 30_000).catch(() => undefined);
        if (!minerStop) await sleep(MINER_PERIOD_MS);
      }
    })();
    await waitMined(rpc, fundTxids);
    // Everything of the registries happens after this height: readers and writers start scanning here.
    const startHeight = (await rpc.tip()) + 1;
    const rootRecord: ZcashRecord = { type: "set_root", kind: "MOCK", p256: toHex(o.trustedRoot) };
    await waitMined(rpc, [await keys.owner.post(rootRecord), await keys.vpnOwner.post(rootRecord)]);

    const readerOf = (owner: ZcashKeyWriter) => new ZcashRegistry({ rpcUrl, network: NETWORK, owner: owner.address, startHeight });
    const registry = readerOf(keys.owner);
    const vpnRegistry = readerOf(keys.vpnOwner);

    const keyOf = (reg: RegistryName, signer: Signer): ZcashKeyWriter => {
      if (signer === "owner") return reg === "llm" ? keys.owner : keys.vpnOwner;
      if (signer !== "operator" && signer !== "operator2" && signer !== "stranger") throw new Error(`unknown signer: ${String(signer)}`);
      return keys[signer];
    };
    const operatorKey = (account: OperatorAccount): ZcashKeyWriter => {
      if (!OPERATORS.includes(account)) throw new Error(`unknown operator account: ${String(account)}`);
      return keys[account];
    };
    const postMined = async (w: ZcashKeyWriter, r: ZcashRecord): Promise<void> => {
      if (stopped) throw new Error("stack is stopped");
      await waitMined(rpc, [await w.post(r)]);
    };
    const adminOf = new WeakMap<ChainAdmin, RegistryName>();
    const makeAdmin = (reg: RegistryName, signer: Signer): ChainAdmin => {
      const w = keyOf(reg, signer);
      const a: ChainAdmin = {
        allowCompose: (h) => postMined(w, { type: "allow_compose", hash: h }),
        revokeCompose: (h) => postMined(w, { type: "revoke_compose", hash: h }),
        allowOs: (h) => postMined(w, { type: "allow_os", hash: h }),
        revokeOs: (h) => postMined(w, { type: "revoke_os", hash: h }),
        approveOperator: (account, orgId) => postMined(w, { type: "approve_operator", hash160: toHex(operatorKey(account).hash160), org_id: orgId }),
        revokeOperator: (account) => postMined(w, { type: "revoke_operator", hash160: toHex(operatorKey(account).hash160) }),
      };
      adminOf.set(a, reg);
      return a;
    };
    const callOn = (reg: RegistryName): CallFn => async (signer, method, args) => {
      try {
        await postMined(keyOf(reg, signer), ownerRecordOf(method, args));
      } catch (e) {
        const msg = e instanceof Error ? e.message : String(e);
        throw new Error(msg.startsWith(`${method} failed`) ? msg : `${method} failed: ${msg}`);
      }
      return undefined;
    };
    const contractId = registry.contractId;
    const vpnContractId = vpnRegistry.contractId;

    return {
      chain: "zcash",
      rpcUrl,
      contractId,
      vpnContractId,
      registry,
      vpnRegistry,
      accounts: { owner: keys.owner.address, operator: keys.operator.address, operator2: keys.operator2.address, stranger: keys.stranger.address },
      admin: makeAdmin("llm", "owner"),
      vpnAdmin: makeAdmin("vpn", "owner"),
      asStranger: (a) => {
        const reg = adminOf.get(a);
        if (reg === undefined) throw new Error("asStranger: not an admin of this stack");
        return makeAdmin(reg, "stranger");
      },
      view: async () => {
        throw new Error("view: the Zcash registry has no contract (use stack.registry)");
      },
      call: callOn("llm"),
      callVpn: callOn("vpn"),
      instanceEnv: async (op, registries) => ({
        PLR_CHAIN: "zcash",
        PLR_ZCASH_RPC: rpcUrl,
        PLR_ZCASH_NETWORK: NETWORK,
        ...(registries.includes("llm") ? { PLR_ZCASH_OWNER: keys.owner.address } : {}),
        ...(registries.includes("vpn") ? { PLR_ZCASH_VPN_OWNER: keys.vpnOwner.address } : {}),
        PLR_ZCASH_KEY: toHex(operatorKey(op).secretKey),
        PLR_ZCASH_START_HEIGHT: String(startHeight),
      }),
      clientEnvLines: () => [
        "PLR_CHAIN=zcash",
        `PLR_ZCASH_RPC=${rpcUrl}`,
        `PLR_ZCASH_NETWORK=${NETWORK}`,
        `PLR_ZCASH_OWNER=${keys.owner.address}`,
        `PLR_ZCASH_START_HEIGHT=${startHeight}`,
        `PLR_REGISTRY=${contractId}`,
        `PLR_VPN_REGISTRY=${vpnContractId}`,
      ],
      ownerFile: () => ({
        chain: "zcash",
        rpc_url: rpcUrl,
        network: NETWORK,
        owner: { address: keys.owner.address, secret_key: toHex(keys.owner.secretKey) },
        vpn_owner: { address: keys.vpnOwner.address, secret_key: toHex(keys.vpnOwner.secretKey) },
      }),
      exportSigner: (signer) => {
        const k = keyOf("llm", signer);
        return { accountId: k.address, secretKey: toHex(k.secretKey) };
      },
      stop,
    };
  } catch (e) {
    await stop();
    throw e;
  }
}
