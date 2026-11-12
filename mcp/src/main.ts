/** stdio entry: `node provenexit-mcp.mjs`. Config: PLR_VPN_URL, PLR_VPN_REGISTRY, PLR_TRUSTED_ROOT, PLR_NEAR_RPC (defaults: the live testnet exit). */
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { createServer } from "./server.js";

await createServer().connect(new StdioServerTransport());
