// Minimal in-process EVM JSON-RPC node with a PlrRegistry model (SPEC-CHAINS §9) for unit tests (anvil cannot run
// inside the test sandbox). Implements just what viem's readContract / simulateContract / writeContract /
// waitForTransactionReceipt use; reverts are JSON-RPC errors carrying ABI-encoded custom errors.
import { createServer, type Server } from "node:http";
import type { AddressInfo } from "node:net";
import { createHash } from "node:crypto";
import {
  decodeFunctionData,
  encodeAbiParameters,
  encodeErrorResult,
  encodeEventTopics,
  encodeFunctionResult,
  keccak256,
  parseTransaction,
  recoverTransactionAddress,
  type Hex,
  type TransactionSerialized,
} from "viem";
import { PLR_REGISTRY_ABI } from "../../src/chains/evm-abi.js";

const sha256 = (b: Buffer) => createHash("sha256").update(b).digest();
const hb = (h: string) => Buffer.from(h.replace(/^0x/, ""), "hex");

export class Revert extends Error {
  constructor(readonly errorName: string) {
    super(errorName);
  }
}

interface Inst {
  composeHash: Hex; osMeasurement: Hex; x25519: Hex; ed25519: Hex; operator: string;
  registeredAtMs: bigint; expiresAtMs: bigint; nextSeq: bigint;
}
interface Anchor { keyHash: Hex; root: Hex; firstSeq: bigint; count: bigint; atMs: bigint; sig: Hex }

export class RegistryModel {
  owner: string;
  rootKind = 1;
  rootP256: Hex;
  compose = new Set<string>();
  os = new Set<string>();
  operators = new Map<string, string>();
  instances = new Map<string, Inst>();
  quotes = new Map<string, Hex>();
  anchors: Anchor[] = [];
  nowMs = () => BigInt(Date.now());
  constructor(readonly chainId: number, readonly address: string, owner: string, rootP256: Hex, readonly ttlMs = 86_400_000n) {
    this.owner = owner.toLowerCase();
    this.rootP256 = rootP256;
  }
  get contractId(): string {
    return `evm:${this.chainId}:${this.address}`;
  }
  regNonce(c: string, o: string): Buffer {
    const cb = Buffer.from(c), ob = Buffer.from(o);
    return sha256(Buffer.concat([Buffer.from("PLR-v1/register/2"), Buffer.of(cb.length), cb, Buffer.of(ob.length), ob]));
  }
  /** Executes `data` from `from`; returns { result, logs } or throws Revert. */
  exec(from: string, data: Hex, write: boolean): { result: Hex; logs: { topics: Hex[]; data: Hex }[] } {
    const { functionName, args } = decodeFunctionData({ abi: PLR_REGISTRY_ABI, data });
    const a = (args ?? []) as readonly unknown[];
    const logs: { topics: Hex[]; data: Hex }[] = [];
    const ret = (v: unknown): Hex => encodeFunctionResult({ abi: PLR_REGISTRY_ABI, functionName, result: v } as never);
    const onlyOwner = () => { if (from !== this.owner) throw new Revert("E_UNAUTHORIZED"); };
    const ZERO = `0x${"00".repeat(32)}`;
    switch (functionName) {
      case "contractId": return { result: ret(this.contractId), logs };
      case "owner": return { result: ret(this.owner), logs };
      case "getRoot": return { result: ret([this.rootKind, this.rootP256]), logs };
      case "isComposeAllowed": return { result: ret(this.compose.has(String(a[0]))), logs };
      case "isOsAllowed": return { result: ret(this.os.has(String(a[0]))), logs };
      case "getOperator": return { result: ret(this.operators.get(String(a[0]).toLowerCase()) ?? ""), logs };
      case "getRegistrationQuote": return { result: ret(this.quotes.get(String(a[0])) ?? "0x"), logs };
      case "anchorCount": return { result: ret(BigInt(this.anchors.length)), logs };
      case "getInstance": {
        const i = this.instances.get(String(a[0]));
        const z = ZERO as Hex;
        return { result: ret(i ? [true, i.composeHash, i.osMeasurement, i.x25519, i.ed25519, i.operator, i.registeredAtMs, i.expiresAtMs, i.nextSeq] : [false, z, z, z, z, "0x0000000000000000000000000000000000000000", 0n, 0n, 0n]), logs };
      }
      case "getAnchor": {
        const x = this.anchors[Number(a[0])];
        if (!x) throw new Revert("E_BAD_INPUT");
        return { result: ret([x.keyHash, x.root, x.firstSeq, x.count, x.atMs, x.sig]), logs };
      }
      case "allowCompose": onlyOwner(); if (write) this.compose.add(String(a[0])); return { result: "0x", logs };
      case "revokeCompose": onlyOwner(); if (write) this.compose.delete(String(a[0])); return { result: "0x", logs };
      case "allowOs": onlyOwner(); if (write) this.os.add(String(a[0])); return { result: "0x", logs };
      case "revokeOs": onlyOwner(); if (write) this.os.delete(String(a[0])); return { result: "0x", logs };
      case "approveOperator": onlyOwner(); if (write) this.operators.set(String(a[0]).toLowerCase(), String(a[1])); return { result: "0x", logs };
      case "revokeOperator": onlyOwner(); if (write) this.operators.delete(String(a[0]).toLowerCase()); return { result: "0x", logs };
      case "registerInstance": {
        const [x, ed, c, o, q] = a as [Hex, Hex, Hex, Hex, Hex];
        if (!this.operators.get(from)) throw new Revert("E_OPERATOR_UNAPPROVED");
        const kh = `0x${sha256(Buffer.concat([Buffer.from("PLR-v1"), hb(x), hb(ed)])).toString("hex")}` as Hex;
        const qb = hb(q);
        if (qb.length !== 828 || qb[0] !== 4 || qb[2] !== 2 || qb[4] !== 0x81) throw new Revert("E_QUOTE_FORMAT");
        if (`0x${qb.subarray(568, 600).toString("hex")}` !== kh) throw new Revert("E_REPORT_DATA");
        if (!qb.subarray(600, 632).equals(this.regNonce(this.contractId, from))) throw new Revert("E_REPORT_DATA");
        // first registrant owns the key while approved; a revoked holder's key may be taken over (fresh record)
        const held = this.instances.get(kh);
        const cur = held && (held.operator === from || this.operators.get(held.operator)) ? held : undefined;
        if (cur && cur.operator !== from) throw new Revert("E_UNAUTHORIZED");
        if (write) {
          const now = this.nowMs();
          this.instances.set(kh, cur
            ? { ...cur, composeHash: c, osMeasurement: o, expiresAtMs: now + this.ttlMs }
            : { composeHash: c, osMeasurement: o, x25519: x, ed25519: ed, operator: from, registeredAtMs: now, expiresAtMs: now + this.ttlMs, nextSeq: 0n });
          this.quotes.set(kh, q);
        }
        return { result: "0x", logs };
      }
      case "anchorReceipts": {
        const [kh, root, first, count, sig] = a as [Hex, Hex, bigint, bigint, Hex];
        const i = this.instances.get(kh);
        const now = this.nowMs();
        if (!i || now >= i.expiresAtMs) throw new Revert("E_INSTANCE_NOT_REGISTERED");
        if (from !== i.operator) throw new Revert("E_UNAUTHORIZED");
        if (!this.compose.has(i.composeHash)) throw new Revert("E_COMPOSE_NOT_ALLOWED");
        if (!this.os.has(i.osMeasurement)) throw new Revert("E_OS_NOT_ALLOWED");
        if (count === 0n || count > 10_000n || first !== i.nextSeq) throw new Revert("E_SEQ");
        if (hb(sig).length !== 64) throw new Revert("E_BAD_INPUT");
        if (write) {
          const id = BigInt(this.anchors.length);
          i.nextSeq = first + count;
          this.anchors.push({ keyHash: kh, root, firstSeq: first, count, atMs: now, sig });
          logs.push({
            topics: encodeEventTopics({ abi: PLR_REGISTRY_ABI, eventName: "ReceiptsAnchored", args: { id, keyHash: kh } }) as Hex[],
            data: encodeAbiParameters(
              [{ type: "bytes32" }, { type: "uint64" }, { type: "uint64" }, { type: "uint64" }, { type: "bytes" }],
              [root, first, count, now, sig],
            ),
          });
        }
        return { result: "0x", logs };
      }
      default:
        throw new Error(`fake: ${functionName} not implemented`);
    }
  }
}

export interface FakeNode {
  url: string;
  model: RegistryModel;
  chainId: number;
  /** method → count of calls */
  calls: Map<string, number>;
  /** Per-method override: return a raw JSON-RPC reply body (object), "hang", or undefined (normal handling). */
  override?: (method: string, params: unknown[]) => unknown | "hang" | undefined;
  /** Transactions included, in order. */
  txs: { from: string; nonce: number; hash: Hex }[];
  close(): Promise<void>;
}

const q = (n: bigint | number) => `0x${BigInt(n).toString(16)}`;

export async function startFakeNode(o: { chainId: number; address: string; owner: string; rootP256: Hex; reportedChainId?: number }): Promise<FakeNode> {
  const model = new RegistryModel(o.chainId, o.address.toLowerCase(), o.owner, o.rootP256);
  const nonces = new Map<string, number>();
  const receipts = new Map<string, Record<string, unknown>>();
  let block = 1n;
  const node: FakeNode = { url: "", model, chainId: o.chainId, calls: new Map(), txs: [], close: async () => {} };
  const handle = async (method: string, params: unknown[]): Promise<{ result?: unknown; error?: unknown }> => {
    const revert = (e: Revert) => ({ error: { code: 3, message: "execution reverted", data: encodeErrorResult({ abi: PLR_REGISTRY_ABI, errorName: e.errorName as never }) } });
    switch (method) {
      case "eth_chainId": return { result: q(o.reportedChainId ?? o.chainId) };
      case "eth_blockNumber": return { result: q(block) };
      case "eth_getBlockByNumber": return { result: { number: q(block), hash: keccak256(`0x${block.toString(16).padStart(2, "0")}` as Hex), baseFeePerGas: "0x3b9aca00", timestamp: q(Math.floor(Date.now() / 1000)), gasLimit: "0x1c9c380", transactions: [] } };
      case "eth_maxPriorityFeePerGas": return { result: "0x3b9aca00" };
      case "eth_gasPrice": return { result: "0x77359400" };
      case "eth_estimateGas":
      case "eth_call": {
        const t = params[0] as { to?: string; from?: string; data?: Hex };
        if ((t.to ?? "").toLowerCase() !== model.address) return { result: "0x" };
        try {
          const r = model.exec((t.from ?? "0x0000000000000000000000000000000000000000").toLowerCase(), t.data ?? "0x", false);
          return { result: method === "eth_estimateGas" ? "0x7a120" : r.result };
        } catch (e) {
          if (e instanceof Revert) return revert(e);
          throw e;
        }
      }
      case "eth_getTransactionCount": return { result: q(nonces.get(String(params[0]).toLowerCase()) ?? 0) };
      case "eth_sendRawTransaction": {
        const raw = params[0] as TransactionSerialized;
        const tx = parseTransaction(raw);
        const from = (await recoverTransactionAddress({ serializedTransaction: raw })).toLowerCase();
        const want = nonces.get(from) ?? 0;
        if (tx.nonce !== want) return { error: { code: -32000, message: tx.nonce! < want ? "nonce too low" : "nonce too high" } };
        if (tx.chainId !== o.chainId) return { error: { code: -32000, message: "invalid chain id" } };
        nonces.set(from, want + 1);
        const hash = keccak256(raw);
        block += 1n;
        let status = "0x1";
        let logs: { topics: Hex[]; data: Hex }[] = [];
        try {
          logs = model.exec(from, tx.data ?? "0x", true).logs;
        } catch (e) {
          if (!(e instanceof Revert)) throw e;
          status = "0x0";
        }
        node.txs.push({ from, nonce: want, hash });
        const blockHash = keccak256(hash);
        receipts.set(hash, {
          transactionHash: hash, transactionIndex: "0x0", blockHash, blockNumber: q(block), from, to: tx.to, cumulativeGasUsed: "0x5208",
          gasUsed: "0x5208", effectiveGasPrice: "0x3b9aca00", contractAddress: null, type: "0x2", status, logsBloom: `0x${"00".repeat(256)}`,
          logs: logs.map((l, i) => ({ address: model.address, topics: l.topics, data: l.data, blockHash, blockNumber: q(block), transactionHash: hash, transactionIndex: "0x0", logIndex: q(i), removed: false })),
        });
        return { result: hash };
      }
      case "eth_getTransactionReceipt": return { result: receipts.get(String(params[0])) ?? null };
      case "eth_getTransactionByHash": return { result: null };
      default: return { error: { code: -32601, message: `method ${method} not found` } };
    }
  };
  const server: Server = createServer((req, res) => {
    const chunks: Buffer[] = [];
    req.on("data", (c: Buffer) => chunks.push(c));
    req.on("end", () => {
      void (async () => {
        const body = JSON.parse(Buffer.concat(chunks).toString("utf8")) as { id: number; method: string; params?: unknown[] };
        node.calls.set(body.method, (node.calls.get(body.method) ?? 0) + 1);
        const ov = node.override?.(body.method, body.params ?? []);
        if (ov === "hang") return;
        const reply = ov !== undefined ? ov : { jsonrpc: "2.0", id: body.id, ...(await handle(body.method, body.params ?? [])) };
        res.writeHead(200, { "content-type": "application/json" });
        res.end(JSON.stringify(reply));
      })().catch((e: unknown) => {
        res.writeHead(500);
        res.end(String(e));
      });
    });
  });
  await new Promise<void>((ok) => server.listen(0, "127.0.0.1", ok));
  node.url = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
  node.close = () => new Promise<void>((ok) => { server.closeAllConnections(); server.close(() => ok()); });
  return node;
}
