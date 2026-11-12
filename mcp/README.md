# ProvenExit MCP server

Lets an AI agent (Claude Code, Claude Desktop, any MCP client) check the ProvenExit VPN exit and fetch web pages
through it. It runs on your machine over stdio, as one self-contained file (Node 22+, no install step).

Tools:

- `verify_exit`: runs the same checks as `vpn verify` (Intel TDX quote, approved build on the NEAR registry, logging
  off) and returns the verdict, the error code if refused, and the ordered checks with `ok` / `detail`.
- `fetch_via_exit({url, max_bytes?})`: GET an `http(s)` URL on port 80 or 443 through an attested tunnel. It verifies
  the exit first; if any check fails nothing is fetched and the error code is returned (for example
  `E_COMPOSE_NOT_ALLOWED` after the owner revoked the build). No direct connection is made and the exit resolves
  the hostname (remote DNS). Returns the status, a few headers and the body as text, cut at `max_bytes` (default 20000, max 1000000).
- `registry_status`: the NEAR registry: owner, root, contract code hash, number of full-access keys, the history of
  owner calls and registrations with transaction hashes, and the registered exit instance.

## Install

Build once (or use the committed `mcp/dist/provenexit-mcp.mjs`):

```sh
npm ci && npx tsc -b && node mcp/build.mjs
```

Claude Code:

```sh
claude mcp add provenexit -- node /path/to/provenexit-mcp.mjs
```

Claude Desktop, in `claude_desktop_config.json`:

```json
{ "mcpServers": { "provenexit": { "command": "node", "args": ["/path/to/provenexit-mcp.mjs"] } } }
```

Configuration is optional. The defaults are the live testnet deployment (`deploy/testnet/env.live`, baked in at
build time); override with `PLR_VPN_URL`, `PLR_VPN_REGISTRY`, `PLR_VPN_REGISTRY_CODE_HASH`, `PLR_TRUSTED_ROOT`, `PLR_NEAR_RPC`.

## Trust note

Only what goes through `fetch_via_exit` is protected by the exit. The agent's other traffic (its model API calls,
its other tools, any command it runs) does not use the exit. The exit sees the destinations of the requests you send
through it; TLS hides the content, not the host. Testnet only; see [`docs/LIMITS.md`](../docs/LIMITS.md).
