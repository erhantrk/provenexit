// Fake Soroban RPC for StellarRegistryWriter unit tests: simulateTransaction (handler-driven), getLedgerEntries (an
// account entry with a sequence number), sendTransaction (records the signed envelope; scripted status) and
// getTransaction (NOT_FOUND only: the success path, which needs real transaction meta, is covered by the live smoke).
import { createServer, type Server } from "node:http";
import type { AddressInfo } from "node:net";
import { Keypair, SorobanDataBuilder, TransactionBuilder, xdr, type Transaction } from "@stellar/stellar-sdk";

export type SimHandler = (fn: string, args: xdr.ScVal[]) => xdr.ScVal | { error: string };

export interface FakeStellar {
  url: string;
  sims: string[];
  sent: Transaction[];
  /** status returned by sendTransaction (default PENDING) */
  sendStatus: "PENDING" | "TRY_AGAIN_LATER" | "ERROR";
  getTx: number;
  /** When set, simulations also carry a restore preamble with this resource fee (archived entries). */
  restoreFee: string | null;
  close(): Promise<void>;
}

export async function startFakeStellar(passphrase: string, handler: SimHandler): Promise<FakeStellar> {
  const f: FakeStellar = { url: "", sims: [], sent: [], sendStatus: "PENDING", getTx: 0, restoreFee: null, close: async () => {} };
  const txData = new SorobanDataBuilder().build().toXdr("base64");
  const server: Server = createServer((req, res) => {
    const chunks: Buffer[] = [];
    req.on("data", (c: Buffer) => chunks.push(c));
    req.on("end", () => {
      const body = JSON.parse(Buffer.concat(chunks).toString("utf8")) as { id: number; method: string; params: Record<string, unknown> };
      const send = (result: unknown) => {
        res.writeHead(200, { "content-type": "application/json" });
        res.end(JSON.stringify({ jsonrpc: "2.0", id: body.id, result }));
      };
      switch (body.method) {
        case "simulateTransaction": {
          const tx = TransactionBuilder.fromXDR(String(body.params.transaction), passphrase) as Transaction;
          const op = tx.operations[0] as unknown as { func: xdr.HostFunction };
          if (op.func.type !== "hostFunctionTypeInvokeContract") return send({ error: "bad op", latestLedger: 1, events: [] });
          const fn = op.func.invokeContract.functionName.toString();
          f.sims.push(fn);
          const r = handler(fn, op.func.invokeContract.args);
          if ("error" in r && typeof r.error === "string") return send({ error: r.error, latestLedger: 1, events: [] });
          const restorePreamble = f.restoreFee === null ? undefined : { minResourceFee: f.restoreFee, transactionData: txData };
          return send({ latestLedger: 1, minResourceFee: "100", transactionData: txData, results: [{ auth: [], xdr: (r as xdr.ScVal).toXdr("base64") }], restorePreamble });
        }
        case "getLedgerEntries": {
          const keyB64 = (body.params.keys as string[])[0]!;
          const key = xdr.LedgerKey.fromXdr(keyB64, "base64");
          if (key.type !== "account") return send({ entries: [], latestLedger: 1 });
          const entry = new xdr.AccountEntry({
            accountId: key.account.accountId, balance: 10_000_000_000n, seqNum: 41n, numSubEntries: 0, inflationDest: null, flags: 0,
            homeDomain: "", thresholds: new Uint8Array([1, 0, 0, 0]), signers: [], ext: xdr.AccountEntryExt.v0(),
          });
          return send({ entries: [{ key: keyB64, xdr: xdr.LedgerEntryData.account(entry).toXdr("base64"), lastModifiedLedgerSeq: 1 }], latestLedger: 1 });
        }
        case "sendTransaction": {
          f.sent.push(TransactionBuilder.fromXDR(String(body.params.transaction), passphrase) as Transaction);
          const hash = Buffer.from((f.sent.at(-1) as Transaction).hash()).toString("hex");
          const r: Record<string, unknown> = { status: f.sendStatus, hash, latestLedger: 1, latestLedgerCloseTime: "1" };
          return send(r);
        }
        case "getTransaction":
          f.getTx++;
          return send({ status: "NOT_FOUND", latestLedger: 1, latestLedgerCloseTime: "1", oldestLedger: 1, oldestLedgerCloseTime: "1" });
        default:
          res.writeHead(200, { "content-type": "application/json" });
          return res.end(JSON.stringify({ jsonrpc: "2.0", id: body.id, error: { code: -32601, message: "method not found" } }));
      }
    });
  });
  await new Promise<void>((ok) => server.listen(0, "127.0.0.1", ok));
  f.url = `http://127.0.0.1:${(server.address() as AddressInfo).port}/rpc`;
  f.close = () => new Promise<void>((ok) => { server.closeAllConnections(); server.close(() => ok()); });
  return f;
}

/** `#[contracttype]` struct ScVal (keys sorted). */
export function scStructOf(fields: Record<string, xdr.ScVal>): xdr.ScVal {
  return xdr.ScVal.scvMap(Object.keys(fields).sort().map((k) => new xdr.ScMapEntry({ key: xdr.ScVal.scvSymbol(k), val: fields[k]! })));
}

export const signedBy = (tx: Transaction, kp: Keypair): boolean =>
  tx.signatures.some((s) => kp.verify(tx.hash(), Buffer.from(s.signature.value)));
