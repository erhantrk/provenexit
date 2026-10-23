// Minimal NEAR JSON-RPC `query/call_function` server backed by a RegistryReader (for NearRegistry + CLI tests).
import { createServer, type Server } from "node:http";
import type { AddressInfo } from "node:net";
import type { RegistryReader } from "@plr/shared";

export type ViewHandler = (method: string, args: Record<string, unknown>) => Promise<unknown>;

export function registryHandler(reg: RegistryReader): ViewHandler {
  return async (method, args) => {
    switch (method) {
      case "get_root": return reg.getRoot();
      case "is_compose_allowed": return reg.isComposeAllowed(args.hash as string);
      case "is_os_allowed": return reg.isOsAllowed(args.hash as string);
      case "get_instance": return reg.getInstance(args.key_hash as string);
      case "get_anchor": return reg.getAnchor(args.id as number);
      default: throw new Error("MethodNotFound");
    }
  };
}

export interface FakeRpc {
  url: string;
  calls: { method: string; args: Record<string, unknown>; finality: unknown }[];
  /** Override the raw JSON-RPC reply (status + body) for the next calls. */
  raw?: (method: string) => { status: number; body: unknown } | "hang" | undefined;
  close(): Promise<void>;
}

export async function startFakeRpc(handler: ViewHandler): Promise<FakeRpc> {
  const rpc: FakeRpc = { url: "", calls: [], close: async () => {} };
  const server: Server = createServer((req, res) => {
    const chunks: Buffer[] = [];
    req.on("data", (c: Buffer) => chunks.push(c));
    req.on("end", () => {
      void (async () => {
        const body = JSON.parse(Buffer.concat(chunks).toString("utf8")) as {
          id: string; method: string;
          params: { request_type: string; account_id: string; method_name: string; args_base64: string; finality?: string };
        };
        const p = body.params;
        const args = JSON.parse(Buffer.from(p.args_base64, "base64").toString("utf8")) as Record<string, unknown>;
        rpc.calls.push({ method: p.method_name, args, finality: p.finality });
        const send = (status: number, j: unknown) => {
          res.writeHead(status, { "content-type": "application/json" });
          res.end(JSON.stringify(j));
        };
        const override = rpc.raw?.(p.method_name);
        if (override === "hang") return;
        if (override) return send(override.status, override.body);
        try {
          const value = await handler(p.method_name, args);
          const bytes = [...Buffer.from(JSON.stringify(value), "utf8")];
          send(200, { jsonrpc: "2.0", id: body.id, result: { result: bytes, logs: [], block_height: 1, block_hash: "11111111111111111111111111111111" } });
        } catch (e) {
          send(200, { jsonrpc: "2.0", id: body.id, result: { error: `wasm execution failed: ${(e as Error).message}`, logs: [], block_height: 1, block_hash: "11111111111111111111111111111111" } });
        }
      })();
    });
  });
  await new Promise<void>((ok) => server.listen(0, "127.0.0.1", ok));
  rpc.url = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
  rpc.close = () => new Promise<void>((ok) => { server.closeAllConnections(); server.close(() => ok()); });
  return rpc;
}
