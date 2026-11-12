# provenexit

Check a VPN exit before you send it anything. The exit runs inside an Intel TDX confidential VM; this command checks
its Intel-signed quote (genuine hardware, debug off, the approved image with logging off) and asks a NEAR registry
whether that build is still allowed. NEAR testnet only.

```sh
npx provenexit verify     # checks the live exit, prints every check and VERIFIED or REFUSED
npx provenexit inspect    # shows what the exit attests to (image, compose hash, OS measurement)
npx provenexit connect    # verifies, then runs a local SOCKS5 proxy through the exit (127.0.0.1:18180)
```

Use the proxy with `socks5h://` (names resolved by the exit), e.g.
`curl -x socks5h://127.0.0.1:18180 https://ifconfig.me`. Only TCP through the proxy is protected.

With no settings it checks the live testnet deployment. Override with `PLR_VPN_URL`, `PLR_VPN_REGISTRY`,
`PLR_NEAR_RPC` and `PLR_TRUSTED_ROOT`; `npx provenexit --help` lists everything (`verify`, `inspect` and `connect`
are short for `vpn verify`, `vpn inspect` and `vpn`).

MCP server for AI agents (verify the exit, fetch pages only through it, refuse if any check fails):

```sh
claude mcp add provenexit -- npx -y -p provenexit provenexit-mcp
```

Live status: https://provenexit.vercel.app · Source, limits and how to reproduce the exit image:
https://github.com/erhantrk/provenexit · MIT license.
