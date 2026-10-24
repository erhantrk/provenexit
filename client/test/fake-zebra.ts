// Minimal Zebra JSON-RPC (getblockcount / getblockhash / getblock <hash> 0|2 / getrawtransaction <txid> 0) over an
// in-memory chain of synthetic blocks, plus helpers to build signed-looking PLR record transactions (SPEC-CHAINS §5,
// §7) for ZcashRegistry tests. Blocks and transactions are real serialized v5 bytes (signatures are random bytes:
// the reader trusts consensus for them, but checks that every spent coin is P2PKH(author)).
import { createServer, type Server } from "node:http";
import type { AddressInfo } from "node:net";
import { randomBytes } from "node:crypto";
import {
  ZCASH_TX, buildZcashBlock, encodeZcashRecord, hash160, opReturnScript, p2pkhScript, parseZcashBlock, serializeTransparentTx,
  tAddress, toHex, zcashBlockJson, zcashTxid, zcashTxidFromRpc, zcashTxidToRpc, type ZcashRecord, type ZcashTx,
} from "@plr/shared";

/** A serialized transaction (RPC txid + bytes). */
export interface FakeTx {
  txid: string;
  raw: Uint8Array;
}

export interface FakeBlock {
  hash: string;
  height: number;
  time: number;
  raw: Uint8Array;
  tx: FakeTx[];
}

export type Override = (method: string, params: unknown[]) => { status: number; body: unknown } | "hang" | undefined;

export interface FakeZebra {
  url: string;
  blocks: FakeBlock[];
  calls: { method: string; params: unknown[] }[];
  override?: Override;
  /** Appends a block with these transactions (a coinbase is added in front; time defaults to now, seconds). */
  mine(txs?: FakeTx[], time?: number): FakeBlock;
  /** Drops blocks above `height` (a reorg; mine the replacement chain afterwards). */
  truncate(height: number): void;
  close(): Promise<void>;
}

export const nowSec = () => Math.floor(Date.now() / 1000);

/** Every transaction ever built by these helpers (funding coins live here; served by getrawtransaction). */
const ALL_TXS = new Map<string, Uint8Array>();

const BRANCH_ID = 0x4dec4df0;

/** Serializes a transparent v5 transaction and registers it for getrawtransaction. */
export function rawTx(
  vin: { prev: Uint8Array; index: number; scriptSig: Uint8Array }[],
  vout: { value?: bigint; script: Uint8Array }[],
): FakeTx {
  const t: ZcashTx = {
    header: ZCASH_TX.HEADER_V5, versionGroupId: ZCASH_TX.VERSION_GROUP_ID_V5, consensusBranchId: BRANCH_ID, lockTime: 0, expiryHeight: 0,
    vin: vin.map((i) => ({ prevTxid: i.prev, prevIndex: i.index, scriptSig: i.scriptSig, sequence: 0xffffffff })),
    vout: vout.map((o) => ({ value: o.value ?? 0n, script: o.script })),
    sapling: { spends: [], outputs: [], valueBalance: 0n, anchor: null, spendProofs: [], spendAuthSigs: [], outputProofs: [], bindingSig: null },
    orchard: { actions: [], flags: 0, valueBalance: 0n, anchor: null, proofs: new Uint8Array(0), spendAuthSigs: [], bindingSig: null },
  };
  const raw = serializeTransparentTx(t);
  const txid = zcashTxidToRpc(zcashTxid(raw));
  ALL_TXS.set(txid, raw);
  return { txid, raw };
}

/** A coinbase-shaped transaction (null outpoint, unique scriptSig) paying `scripts`. */
export function coinbaseTx(scripts: Uint8Array[] = [p2pkhScript(new Uint8Array(20))]): FakeTx {
  return rawTx([{ prev: new Uint8Array(32), index: 0xffffffff, scriptSig: Uint8Array.from(randomBytes(8)) }], scripts.map((script) => ({ value: 100_000_000n, script })));
}

export async function startFakeZebra(): Promise<FakeZebra> {
  const genesis = buildZcashBlock({ prev: "00".repeat(32), time: nowSec(), txs: [coinbaseTx().raw] });
  const z: FakeZebra = {
    url: "",
    blocks: [],
    calls: [],
    mine(txs = [], time = nowSec()) {
      const prev = z.blocks[z.blocks.length - 1]!.hash;
      const all = [coinbaseTx(), ...txs];
      const { raw, hash } = buildZcashBlock({ prev, time, txs: all.map((t) => t.raw) });
      const b = { hash, height: z.blocks.length, time, raw, tx: all };
      z.blocks.push(b);
      return b;
    },
    truncate(height) {
      z.blocks.length = height + 1;
    },
    close: async () => {},
  };
  z.blocks.push({ hash: genesis.hash, height: 0, time: nowSec(), raw: genesis.raw, tx: [] });
  const server: Server = createServer((req, res) => {
    const chunks: Buffer[] = [];
    req.on("data", (c: Buffer) => chunks.push(c));
    req.on("end", () => {
      const body = JSON.parse(Buffer.concat(chunks).toString("utf8")) as { id: unknown; method: string; params: unknown[] };
      z.calls.push({ method: body.method, params: body.params });
      const send = (status: number, j: unknown) => {
        res.writeHead(status, { "content-type": "application/json" });
        res.end(JSON.stringify(j));
      };
      const o = z.override?.(body.method, body.params);
      if (o === "hang") return;
      if (o) return send(o.status, o.body);
      const ok = (result: unknown) => send(200, { jsonrpc: "2.0", id: body.id, result });
      const err = (message: string) => send(200, { jsonrpc: "2.0", id: body.id, error: { code: -8, message } });
      switch (body.method) {
        case "getblockcount":
          return ok(z.blocks.length - 1);
        case "getblockhash": {
          const b = z.blocks[body.params[0] as number];
          return b ? ok(b.hash) : err("block height out of range");
        }
        case "getblock": {
          const i = z.blocks.findIndex((b) => b.hash === body.params[0]);
          if (i < 0) return err("block not found");
          const b = z.blocks[i]!;
          if (body.params[1] === 0) return ok(toHex(b.raw));
          if (body.params[1] !== 2) return err("bad verbosity");
          return ok({ hash: b.hash, height: b.height, time: b.time, ...zcashBlockJson(b.height, parseZcashBlock(b.raw)) });
        }
        case "getrawtransaction": {
          const raw = ALL_TXS.get(body.params[0] as string);
          if (raw === undefined || body.params[1] !== 0) return err("No such mempool or main chain transaction");
          return ok(toHex(raw));
        }
        default:
          return err("method not found");
      }
    });
  });
  await new Promise<void>((ok) => server.listen(0, "127.0.0.1", ok));
  z.url = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
  z.close = () => new Promise<void>((ok) => server.close(() => ok()));
  return z;
}

/** A party with a (random) compressed secp256k1-shaped pubkey; ZcashLog trusts consensus for the signature itself. */
export interface Party {
  pub: Uint8Array;
  h160: string;
  addr: string;
}
export function party(): Party {
  const pub = new Uint8Array(33);
  pub[0] = 0x02;
  pub.set(randomBytes(32), 1);
  const h = hash160(pub);
  return { pub, h160: toHex(h), addr: tAddress(h, "regtest") };
}

const push = (b: Uint8Array): Uint8Array => Uint8Array.from([b.length, ...b]);

/** `<71-byte sig ending in SIGHASH_ALL> <pubkey>` */
export function p2pkhScriptSig(pub: Uint8Array, hashType = 0x01): Uint8Array {
  const sig = Uint8Array.from(randomBytes(71));
  sig[70] = hashType;
  return Uint8Array.from([...push(sig), ...push(pub)]);
}

export interface RecordTxOptions {
  /** script of the coin the record spends (default P2PKH(who)); e.g. `6d51` (OP_2DROP OP_1) for a forgery */
  prevoutScript?: Uint8Array;
  /** last byte of the signature push (default SIGHASH_ALL) */
  hashType?: number;
}

/** A transaction carrying `r` signed by `who` (scriptSig = <sig> <pubkey>), spending a fresh coin. */
export function recordTx(who: Party, r: ZcashRecord, o: RecordTxOptions = {}): FakeTx {
  const lock = o.prevoutScript ?? p2pkhScript(hash160(who.pub));
  const fund = coinbaseTx([lock]);
  return rawTx(
    [{ prev: zcashTxidFromRpc(fund.txid), index: 0, scriptSig: p2pkhScriptSig(who.pub, o.hashType) }],
    [{ script: opReturnScript(encodeZcashRecord(r)) }, { value: 99_000_000n, script: p2pkhScript(hash160(who.pub)) }],
  );
}
