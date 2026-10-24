// Minimal Solana JSON-RPC (`getMultipleAccounts`, base64) backed by an in-memory account map, for SolanaRegistry tests.
import { createServer, type Server } from "node:http";
import type { AddressInfo } from "node:net";

export interface FakeAccount {
  owner: string;
  data: Uint8Array;
}

export interface FakeSolanaRpc {
  url: string;
  accounts: Map<string, FakeAccount>;
  calls: { method: string; params: unknown[] }[];
  /** Override the raw reply for the next calls. */
  raw?: (method: string) => { status: number; body: unknown } | undefined;
  close(): Promise<void>;
}

export async function startFakeSolanaRpc(): Promise<FakeSolanaRpc> {
  const rpc: FakeSolanaRpc = { url: "", accounts: new Map(), calls: [], close: async () => {} };
  const server: Server = createServer((req, res) => {
    const chunks: Buffer[] = [];
    req.on("data", (c: Buffer) => chunks.push(c));
    req.on("end", () => {
      const body = JSON.parse(Buffer.concat(chunks).toString("utf8")) as { id: number; method: string; params: unknown[] };
      rpc.calls.push({ method: body.method, params: body.params });
      const send = (status: number, j: unknown) => {
        res.writeHead(status, { "content-type": "application/json" });
        res.end(JSON.stringify(j));
      };
      const o = rpc.raw?.(body.method);
      if (o) return send(o.status, o.body);
      if (body.method !== "getMultipleAccounts") return send(200, { jsonrpc: "2.0", id: body.id, error: { code: -32601, message: "Method not found" } });
      const keys = body.params[0] as string[];
      const value = keys.map((k) => {
        const a = rpc.accounts.get(k);
        return a ? { data: [Buffer.from(a.data).toString("base64"), "base64"], executable: false, lamports: 1_000_000, owner: a.owner, rentEpoch: 18446744073709551615n.toString(), space: a.data.length } : null;
      });
      send(200, { jsonrpc: "2.0", id: body.id, result: { context: { slot: 5 }, value } });
    });
  });
  await new Promise<void>((ok) => server.listen(0, "127.0.0.1", ok));
  rpc.url = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
  rpc.close = () => new Promise<void>((ok) => server.close(() => ok()));
  return rpc;
}
