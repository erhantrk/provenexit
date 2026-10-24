// A fake Solana JSON-RPC for SolanaRegistryWriter tests: accounts from a map, scripted simulate / status replies,
// and a record of every transaction sent.
import { createServer, type Server } from "node:http";
import type { AddressInfo } from "node:net";

export interface FakeAccount {
  owner: string;
  data: Uint8Array;
}

export interface FakeSolana {
  url: string;
  accounts: Map<string, FakeAccount>;
  calls: string[];
  /** Raw (base64-decoded) transactions received by sendTransaction / simulateTransaction. */
  sent: Uint8Array[];
  simulated: Uint8Array[];
  /** `err` of the next simulations (default null). */
  simErr: unknown;
  /** Status of sent signatures (default confirmed, no error); null = unknown. */
  status: { err: unknown; confirmationStatus: string } | null;
  blockHeight: number;
  close(): Promise<void>;
}

export async function startFakeSolana(): Promise<FakeSolana> {
  const f: FakeSolana = {
    url: "", accounts: new Map(), calls: [], sent: [], simulated: [], simErr: null,
    status: { err: null, confirmationStatus: "confirmed" }, blockHeight: 10, close: async () => {},
  };
  const server: Server = createServer((req, res) => {
    const chunks: Buffer[] = [];
    req.on("data", (c: Buffer) => chunks.push(c));
    req.on("end", () => {
      const body = JSON.parse(Buffer.concat(chunks).toString("utf8")) as { id: string; method: string; params: unknown[] };
      f.calls.push(body.method);
      const ok = (result: unknown) => {
        res.writeHead(200, { "content-type": "application/json" });
        res.end(JSON.stringify({ jsonrpc: "2.0", id: body.id, result }));
      };
      const ctx = { slot: 50 };
      switch (body.method) {
        case "getMultipleAccounts": {
          const keys = body.params[0] as string[];
          return ok({
            context: ctx,
            value: keys.map((k) => {
              const a = f.accounts.get(k);
              return a ? { data: [Buffer.from(a.data).toString("base64"), "base64"], executable: false, lamports: 1_000_000, owner: a.owner, rentEpoch: 0, space: a.data.length } : null;
            }),
          });
        }
        case "getAccountInfo": {
          const a = f.accounts.get(body.params[0] as string);
          return ok({
            context: ctx,
            value: a ? { data: [Buffer.from(a.data).toString("base64"), "base64"], executable: false, lamports: 1_000_000, owner: a.owner, rentEpoch: 0, space: a.data.length } : null,
          });
        }
        case "getLatestBlockhash":
          return ok({ context: ctx, value: { blockhash: "GHtXQBsoZHVnNFa9YevAzFr17DJjgHXk3ycTKD5xD3Zi", lastValidBlockHeight: 100 } });
        case "simulateTransaction":
          f.simulated.push(Buffer.from(body.params[0] as string, "base64"));
          return ok({ context: ctx, value: { err: f.simErr, logs: [], accounts: null, unitsConsumed: 1000, returnData: null } });
        case "sendTransaction":
          f.sent.push(Buffer.from(body.params[0] as string, "base64"));
          return ok("5VERv8NMvzbJMEkV8xnrLkEaWRtSz9CosKDYjCJjBRnbJLgp8uirBgmQpjKhoR4tjF3ZpRzrFmBV6UjKdiSZkQUW");
        case "getSignatureStatuses":
          return ok({ context: ctx, value: [f.status === null ? null : { slot: 49, confirmations: 0, err: f.status.err, confirmationStatus: f.status.confirmationStatus }] });
        case "getBlockHeight":
          return ok(f.blockHeight);
        case "getSlot":
          return ok(50);
        default:
          res.writeHead(200, { "content-type": "application/json" });
          return res.end(JSON.stringify({ jsonrpc: "2.0", id: body.id, error: { code: -32601, message: "Method not found" } }));
      }
    });
  });
  await new Promise<void>((ok) => server.listen(0, "127.0.0.1", ok));
  f.url = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
  f.close = () => new Promise<void>((ok) => server.close(() => ok()));
  return f;
}
