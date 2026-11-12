/** The ProvenExit MCP server: tools over the attested VPN exit. Transport-agnostic (`main.ts` wires stdio). */
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import { getRegistryStatus, openExit, verifyVpnReport, type StatusOptions, type VerifyReport } from "@plr/client/lite";
import { httpGetOver, parseFetchUrl, parseMaxBytes, UrlRefused } from "./fetch.js";

export interface ServerDeps {
  /** Overrides the configuration (tests; otherwise env variables and the baked-in live defaults). */
  options?: StatusOptions;
  /** Ports `fetch_via_exit` accepts (default 80 and 443). Tests only. */
  allowedPorts?: readonly number[];
}

type ToolResult = { content: { type: "text"; text: string }[]; isError?: boolean };
const json = (v: unknown, isError = false): ToolResult => ({ content: [{ type: "text", text: JSON.stringify(v, null, 2) }], ...(isError ? { isError: true } : {}) });
const msg = (e: unknown): string => (e instanceof Error ? e.message : "error");

const publicReport = (r: VerifyReport): { verdict: string; code: string | null; root: string; checks: VerifyReport["checks"] } => ({
  verdict: r.verdict,
  code: r.code,
  root: r.root,
  checks: r.checks,
});

export function createServer(deps: ServerDeps = {}): McpServer {
  const opts = deps.options ?? {};
  const server = new McpServer({ name: "provenexit", version: "0.1.0" });

  server.registerTool(
    "verify_exit",
    {
      title: "Verify the ProvenExit VPN exit",
      description:
        "Verify the ProvenExit VPN exit right now: Intel TDX quote, approved build on the NEAR registry, logging off. " +
        "Returns the verdict (VERIFIED or REFUSED), the error code when refused, and the ordered list of checks with ok/detail.",
      inputSchema: {},
    },
    async () => {
      try {
        const { client, registry, exitUrl, registryId } = openExit(opts);
        const r = await verifyVpnReport(client, registry);
        return json({ exit: exitUrl, registry: registryId, ...publicReport(r) }, false);
      } catch (e) {
        return json({ verdict: "REFUSED", code: "E_BAD_INPUT", error: msg(e) }, true);
      }
    },
  );

  server.registerTool(
    "fetch_via_exit",
    {
      title: "Fetch a web page through the verified exit",
      description:
        "GET an http(s) URL (ports 80/443 only) through the ProvenExit VPN exit. The exit is verified first; if any check fails " +
        "nothing is fetched and the error code is returned. The request goes through an attested tunnel (no direct connection; " +
        "the exit resolves the hostname). Returns status, a few headers and the body as text, truncated to max_bytes (default 20000).",
      inputSchema: {
        url: z.string().describe("http:// or https:// URL, port 80 or 443"),
        max_bytes: z.number().int().min(1).max(1_000_000).optional().describe("body bytes to return (default 20000)"),
      },
    },
    async (args) => {
      let target;
      let maxBytes;
      try {
        target = parseFetchUrl(args.url, deps.allowedPorts);
        maxBytes = parseMaxBytes(args.max_bytes);
      } catch (e) {
        return json({ refused: true, code: e instanceof UrlRefused ? e.code : "E_BAD_INPUT", error: msg(e) }, true);
      }
      try {
        const { client, registry } = openExit(opts);
        const report = await verifyVpnReport(client, registry);
        if (report.verdict !== "VERIFIED") {
          const failed = report.checks.find((c) => !c.ok && c.detail !== "not checked");
          return json({ refused: true, code: report.code, failed_check: failed?.name ?? null, error: "the exit did not verify; nothing was fetched" }, true);
        }
        const tunnel = await client.connect(target.host, target.port);
        const r = await httpGetOver(tunnel, target, maxBytes);
        return json({ via: "provenexit", status: r.status, headers: r.headers, truncated: r.truncated, bytes: r.bytes, body: r.body });
      } catch (e) {
        const code = (e as { code?: unknown }).code;
        return json({ refused: true, code: typeof code === "string" ? code : "E_FETCH_FAILED", error: typeof code === "string" ? "the exit or the tunnel refused the request" : msg(e) }, true);
      }
    },
  );

  server.registerTool(
    "registry_status",
    {
      title: "ProvenExit registry status",
      description:
        "Read the NEAR registry that approves ProvenExit builds: owner, root, contract code hash, number of full-access keys, " +
        "the public history of owner calls and registrations (with tx hashes), and the registered exit instance.",
      inputSchema: {},
    },
    async () => {
      const s = await getRegistryStatus(opts);
      return json(s, s.error !== null);
    },
  );

  return server;
}
