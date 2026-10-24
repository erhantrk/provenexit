// Minimal Soroban RPC `simulateTransaction` server for StellarRegistry unit tests: decodes the invoked contract
// function + args from the transaction XDR and answers with the handler's ScVal (or a host error string).
import { createServer, type Server } from "node:http";
import type { AddressInfo } from "node:net";
import { SorobanDataBuilder, TransactionBuilder, xdr, type Transaction } from "@stellar/stellar-sdk";

export type SimHandler = (fn: string, args: xdr.ScVal[], contract: string) => xdr.ScVal | { error: string } | "hang" | { raw: unknown };

export interface FakeSoroban {
  url: string;
  calls: { fn: string; contract: string; source: string }[];
  close(): Promise<void>;
}

export async function startFakeSoroban(passphrase: string, handler: SimHandler): Promise<FakeSoroban> {
  const f: FakeSoroban = { url: "", calls: [], close: async () => {} };
  const txData = new SorobanDataBuilder().build().toXdr("base64");
  const server: Server = createServer((req, res) => {
    const chunks: Buffer[] = [];
    req.on("data", (c: Buffer) => chunks.push(c));
    req.on("end", () => {
      const body = JSON.parse(Buffer.concat(chunks).toString("utf8")) as { id: number; method: string; params: { transaction?: string } };
      const send = (j: unknown) => {
        res.writeHead(200, { "content-type": "application/json" });
        res.end(JSON.stringify({ jsonrpc: "2.0", id: body.id, ...(j as object) }));
      };
      if (body.method !== "simulateTransaction" || !body.params.transaction) return send({ error: { code: -32601, message: "method not found" } });
      const tx = TransactionBuilder.fromXDR(body.params.transaction, passphrase) as Transaction;
      const op = tx.operations[0] as unknown as { type: string; func: xdr.HostFunction };
      if (op.type !== "invokeHostFunction" || op.func.type !== "hostFunctionTypeInvokeContract") return send({ error: { code: -1, message: "bad op" } });
      const ic = op.func.invokeContract;
      const fn = ic.functionName.toString();
      const contract = String((op as unknown as { contract?: string }).contract ?? "");
      f.calls.push({ fn, contract, source: tx.source });
      const r = handler(fn, ic.args, contract);
      if (r === "hang") return;
      if ("raw" in r) return send({ result: r.raw });
      if ("error" in r && typeof r.error === "string") return send({ result: { error: r.error, latestLedger: 1, events: [] } });
      send({ result: { latestLedger: 1, minResourceFee: "0", transactionData: txData, results: [{ auth: [], xdr: (r as xdr.ScVal).toXdr("base64") }] } });
    });
  });
  await new Promise<void>((ok) => server.listen(0, "127.0.0.1", ok));
  f.url = `http://127.0.0.1:${(server.address() as AddressInfo).port}/rpc`;
  f.close = () => new Promise<void>((ok) => { server.closeAllConnections(); server.close(() => ok()); });
  return f;
}

/** `#[contracttype]` struct ScVal (keys sorted, as the host encodes maps). */
export function scStructOf(fields: Record<string, xdr.ScVal>): xdr.ScVal {
  const keys = Object.keys(fields).sort();
  return xdr.ScVal.scvMap(keys.map((k) => new xdr.ScMapEntry({ key: xdr.ScVal.scvSymbol(k), val: fields[k]! })));
}
