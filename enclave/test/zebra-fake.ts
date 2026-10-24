/**
 * A fake Zebra JSON-RPC node for unit tests: an in-memory transparent chain with the RPCs the Zcash writer uses
 * (`getblockcount`, `getblockhash`, `getblock <hash> 0|2`, `getrawtransaction <txid> 0`, `getblockchaininfo`,
 * `getaddressutxos`, `sendrawtransaction`). Blocks and transactions are real serialized bytes.
 * `sendrawtransaction` checks what a real node would reject: parse errors, wrong branch id, expired, unknown or
 * mempool-conflicting inputs, bad P2PKH signatures (ZIP-244 sighash), fee below ZIP-317, more than one OP_RETURN or one
 * over 83 bytes.
 */
import http from "node:http";
import type { AddressInfo } from "node:net";
import { secp256k1 } from "@noble/curves/secp256k1.js";
import { randomBytes } from "@noble/hashes/utils.js";
import {
  SIGHASH, ZCASH_TX, buildSignedTransparentTx, buildZcashBlock, hash160, p2pkhScript, parsePushes, parseTAddress, parseZcashTx,
  serializeTransparentTx, toHex, zcashSighash, zcashTxid, zcashTxidFromRpc, zcashTxidToRpc, zip317Fee, type ZcashTx,
} from "@plr/shared";

export const BRANCH_ID = 0x4dec4df0;

interface Coin {
  script: string;
  amount: bigint;
  height: number;
}
interface BlockTx {
  txid: string;
  vin: Record<string, unknown>[];
  vout: { value: number; n: number; scriptPubKey: { hex: string } }[];
}
interface Block {
  hash: string;
  height: number;
  time: number;
  tx: BlockTx[];
  raw: Uint8Array;
}

/** A coinbase-shaped v5 transaction (null outpoint, unique scriptSig) paying `outs`. */
export function coinbaseRaw(outs: { amount: bigint; script: Uint8Array }[]): Uint8Array {
  const t: ZcashTx = {
    header: ZCASH_TX.HEADER_V5, versionGroupId: ZCASH_TX.VERSION_GROUP_ID_V5, consensusBranchId: BRANCH_ID, lockTime: 0, expiryHeight: 0,
    vin: [{ prevTxid: new Uint8Array(32), prevIndex: 0xffffffff, scriptSig: randomBytes(8), sequence: 0xffffffff }],
    vout: outs.map((o) => ({ value: o.amount, script: o.script })),
    sapling: { spends: [], outputs: [], valueBalance: 0n, anchor: null, spendProofs: [], spendAuthSigs: [], outputProofs: [], bindingSig: null },
    orchard: { actions: [], flags: 0, valueBalance: 0n, anchor: null, proofs: new Uint8Array(0), spendAuthSigs: [], bindingSig: null },
  };
  return serializeTransparentTx(t);
}
export interface SentTx {
  txid: string;
  raw: Uint8Array;
  tx: ZcashTx;
  fee: bigint;
  /** spent outpoints "<rpc txid>:<vout>" */
  spends: string[];
}

class RpcError extends Error {
  constructor(readonly code: number, message: string) {
    super(message);
  }
}

export class FakeZebra {
  readonly blocks: Block[] = [];
  readonly utxos = new Map<string, Coin>();
  mempool: SentTx[] = [];
  /** every accepted transaction, in submission order */
  readonly accepted: SentTx[] = [];
  /** every rejected submission (reason) */
  readonly rejected: string[] = [];
  /** RPC calls by method */
  readonly calls = new Map<string, number>();
  /** every mined transaction by RPC txid */
  readonly rawTxs = new Map<string, Uint8Array>();
  /** Test hook: reorder a block's non-coinbase transactions before it is sealed (Zebra does not keep submission order). */
  order: ((txs: SentTx[]) => SentTx[]) | null = null;
  /** Test hooks */
  overrides: Partial<Record<string, (params: unknown[]) => unknown>> = {};
  lastAuth: string | undefined;
  time = 1_800_000_000;
  #server: http.Server | null = null;
  #timer: NodeJS.Timeout | null = null;
  url = "";

  constructor() {
    this.#seal(0, [], [coinbaseRaw([])]);
  }

  /** Builds block `height` from raw transactions (first = coinbase) and appends it. */
  #seal(height: number, tx: BlockTx[], raws: Uint8Array[]): Block {
    const prev = height === 0 ? "00".repeat(32) : this.blocks[height - 1]!.hash;
    const { raw, hash } = buildZcashBlock({ prev, time: this.time, txs: raws });
    for (const r of raws) this.rawTxs.set(zcashTxidToRpc(zcashTxid(r)), r);
    const b: Block = { hash, height, time: this.time, tx, raw };
    this.blocks.push(b);
    return b;
  }

  get tip(): number {
    return this.blocks.length - 1;
  }

  async start(): Promise<string> {
    this.#server = http.createServer((req, res) => {
      this.lastAuth = req.headers.authorization;
      const chunks: Buffer[] = [];
      req.on("data", (c: Buffer) => chunks.push(c));
      req.on("end", () => {
        let id: unknown = null;
        let out: unknown;
        try {
          const body = JSON.parse(Buffer.concat(chunks).toString("utf8")) as { id: unknown; method: string; params?: unknown[] };
          id = body.id;
          this.calls.set(body.method, (this.calls.get(body.method) ?? 0) + 1);
          out = { jsonrpc: "2.0", id, result: this.handle(body.method, body.params ?? []) };
        } catch (e) {
          out = { jsonrpc: "2.0", id, error: { code: e instanceof RpcError ? e.code : -1, message: (e as Error).message } };
        }
        res.writeHead(200, { "content-type": "application/json" });
        res.end(JSON.stringify(out));
      });
    });
    await new Promise<void>((ok) => this.#server!.listen(0, "127.0.0.1", () => ok()));
    this.url = `http://127.0.0.1:${(this.#server.address() as AddressInfo).port}`;
    return this.url;
  }

  /** Mines a block every `ms` (like the harness's background miner). */
  autoMine(ms: number): void {
    this.stopMining();
    this.#timer = setInterval(() => this.mine(), ms);
  }
  stopMining(): void {
    if (this.#timer) clearInterval(this.#timer);
    this.#timer = null;
  }

  async stop(): Promise<void> {
    this.stopMining();
    const s = this.#server;
    if (s) await new Promise<void>((ok) => { s.close(() => ok()); s.closeAllConnections(); });
  }

  handle(method: string, params: unknown[]): unknown {
    const o = this.overrides[method];
    if (o) return o(params);
    switch (method) {
      case "getblockcount":
        return this.tip;
      case "getblockhash": {
        const b = this.blocks[params[0] as number];
        if (!b) throw new RpcError(-8, "height out of range");
        return b.hash;
      }
      case "getblock": {
        const b = this.blocks.find((x) => x.hash === params[0]);
        if (!b) throw new RpcError(-8, "block not found");
        if (params[1] === 0) return toHex(b.raw);
        return { hash: b.hash, height: b.height, time: b.time, tx: b.tx };
      }
      case "getrawtransaction": {
        const raw = this.rawTxs.get(params[0] as string);
        if (!raw || params[1] !== 0) throw new RpcError(-5, "No such mempool or main chain transaction");
        return toHex(raw);
      }
      case "getblockchaininfo":
        return { chain: "test", blocks: this.tip, consensus: { chaintip: "c8e71055", nextblock: BRANCH_ID.toString(16).padStart(8, "0") } };
      case "getaddressutxos": {
        const p = params[0] as { addresses: string[] };
        const scripts = new Map(p.addresses.map((a) => [toHex(p2pkhScript(parseTAddress(a).hash160)), a]));
        const out = [];
        for (const [k, c] of this.utxos) {
          const addr = scripts.get(c.script);
          if (addr === undefined) continue;
          const [txid, vout] = k.split(":");
          out.push({ address: addr, txid, outputIndex: Number(vout), script: c.script, satoshis: Number(c.amount), height: c.height });
        }
        return out;
      }
      case "sendrawtransaction":
        return this.submit(Buffer.from(params[0] as string, "hex"));
      default:
        throw new RpcError(-32601, "method not found");
    }
  }

  submit(raw: Uint8Array): string {
    const reject = (why: string): never => {
      this.rejected.push(why);
      throw new RpcError(-26, why);
    };
    let tx: ZcashTx;
    try {
      tx = parseZcashTx(raw);
    } catch {
      return reject("parse");
    }
    if (tx.consensusBranchId !== BRANCH_ID) reject("branch id");
    if (tx.expiryHeight !== 0 && tx.expiryHeight <= this.tip + 3) reject("expiring soon");
    const spends: string[] = [];
    const amounts: bigint[] = [];
    const scripts: Uint8Array[] = [];
    for (const i of tx.vin) {
      const k = `${zcashTxidToRpc(i.prevTxid)}:${i.prevIndex}`;
      const c = this.utxos.get(k);
      if (!c) reject("missing input");
      if (this.mempool.some((m) => m.spends.includes(k)) || spends.includes(k)) reject("mempool conflict");
      spends.push(k);
      amounts.push(c!.amount);
      scripts.push(Buffer.from(c!.script, "hex"));
    }
    tx.vin.forEach((i, idx) => {
      const pushes = parsePushes(i.scriptSig);
      if (!pushes || pushes.length !== 2) reject("scriptSig");
      const [sig, pub] = pushes as [Uint8Array, Uint8Array];
      if (toHex(p2pkhScript(hash160(pub))) !== toHex(scripts[idx]!)) reject("pubkey does not own coin");
      if (sig[sig.length - 1] !== SIGHASH.ALL) reject("hash type");
      const digest = zcashSighash(raw, { inputIndex: idx, hashType: SIGHASH.ALL, amounts, scriptPubKeys: scripts });
      if (!secp256k1.verify(sig.subarray(0, sig.length - 1), digest, pub, { prehash: false, format: "der", lowS: true })) reject("signature");
    });
    const opReturns = tx.vout.filter((o) => o.script[0] === 0x6a);
    if (opReturns.length > 1 || opReturns.some((o) => o.script.length > 83)) reject("op_return standardness");
    const inSum = amounts.reduce((a, b) => a + b, 0n);
    const outSum = tx.vout.reduce((a, o) => a + o.value, 0n);
    const fee = inSum - outSum;
    if (fee < zip317Fee({ inputs: tx.vin.length, outputScripts: tx.vout.map((o) => o.script) })) reject("fee below ZIP-317");
    const txid = zcashTxidToRpc(zcashTxid(raw));
    const s: SentTx = { txid, raw, tx, fee, spends };
    this.mempool.push(s);
    this.accepted.push(s);
    return txid;
  }

  /** Mines one block with the whole mempool (in submission order). */
  mine(): Block {
    const height = this.blocks.length;
    this.time += 1;
    const cb = coinbaseRaw([]);
    const tx: BlockTx[] = [{ txid: zcashTxidToRpc(zcashTxid(cb)), vin: [{ coinbase: "00" }], vout: [] }];
    const raws = [cb];
    const pool = this.order ? this.order([...this.mempool]) : this.mempool;
    for (const m of pool) {
      raws.push(m.raw);
      for (const k of m.spends) this.utxos.delete(k);
      m.tx.vout.forEach((o, n) => {
        if (o.script[0] !== 0x6a) this.utxos.set(`${m.txid}:${n}`, { script: toHex(o.script), amount: o.value, height });
      });
      tx.push({
        txid: m.txid,
        vin: m.tx.vin.map((i) => ({ txid: zcashTxidToRpc(i.prevTxid), vout: i.prevIndex, scriptSig: { asm: "", hex: toHex(i.scriptSig) } })),
        vout: m.tx.vout.map((o, n) => ({ value: Number(o.value) / 1e8, n, scriptPubKey: { hex: toHex(o.script) } })),
      });
    }
    this.mempool = [];
    return this.#seal(height, tx, raws);
  }

  /** Appends a block of exactly these raw transactions (the first should be a coinbase). */
  sealRaw(raws: Uint8Array[]): Block {
    this.time += 1;
    return this.#seal(this.blocks.length, [], raws);
  }

  /** Mines a block containing only the given mempool transactions (by txid), in that order; the rest stay pending. */
  mineOnly(txids: string[]): Block {
    const keep = this.mempool.filter((m) => !txids.includes(m.txid));
    this.mempool = txids.map((id) => this.mempool.find((m) => m.txid === id)!).filter(Boolean);
    const b = this.mine();
    this.mempool = keep;
    return b;
  }

  /** Credits `amounts` to the P2PKH address of `h160` in a new block (as one funding transaction). */
  fund(h160: Uint8Array, amounts: bigint[]): void {
    const height = this.blocks.length;
    const script = toHex(p2pkhScript(h160));
    const raw = coinbaseRaw(amounts.map((amount) => ({ amount, script: p2pkhScript(h160) })));
    const txid = zcashTxidToRpc(zcashTxid(raw));
    amounts.forEach((amount, n) => this.utxos.set(`${txid}:${n}`, { script, amount, height }));
    this.time += 1;
    this.#seal(height, [{ txid, vin: [{ coinbase: "00" }], vout: amounts.map((a, n) => ({ value: Number(a) / 1e8, n, scriptPubKey: { hex: script } })) }], [raw]);
  }

  /** Signs and submits a record transaction for `sk` (e.g. an owner policy record) using `outpoint` or its first free coin. */
  post(sk: Uint8Array, script: Uint8Array, outpoint?: string): string {
    const h = toHex(p2pkhScript(hash160(secp256k1.getPublicKey(sk, true))));
    const spent = new Set(this.mempool.flatMap((m) => m.spends));
    const coin = [...this.utxos].find(([k, c]) => c.script === h && !spent.has(k) && (outpoint === undefined || k === outpoint));
    if (!coin) throw new Error("no coin");
    const [k, c] = coin;
    const [txid, vout] = k.split(":");
    const fee = zip317Fee({ inputs: 1, outputScripts: [script, Buffer.from(h, "hex")] });
    const raw = buildSignedTransparentTx({
      branchId: BRANCH_ID,
      expiryHeight: this.tip + 40,
      inputs: [{ txid: zcashTxidFromRpc(txid!), vout: Number(vout), amount: c.amount, secretKey: sk }],
      outputs: [{ amount: 0n, script }, { amount: c.amount - fee, script: Buffer.from(h, "hex") }],
    });
    return this.submit(raw);
  }

  /** The `getblock … 2` JSON of every block (for an independent reader). */
  blockJson(): { height: number; time: number; tx: BlockTx[] }[] {
    return this.blocks.map((b) => ({ height: b.height, time: b.time, tx: b.tx }));
  }
}
