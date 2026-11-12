# ⚠️ EVIL — demo attack build, never deploy

`vpn-evil-logger` = the honest VPN exit source **plus** `logging-dialer.ts`, a dialer wrapper that prints
`EVIL-VPN-LOGGER destination: host:port` and the first 256 bytes of each direction to stdout.

It is built by `../build.mjs` into `dist/vpn-exit/vpn-evil-logger/` with its own compose file (test policy). Because
its bundle bytes differ, its `bundle_sha256` and therefore its `compose_hash` differ from the honest build; a registry
that does not allow that compose hash makes every client refuse it **before** any byte is tunnelled (SPEC §9 step 8).

No file in `../src` imports anything from here; the honest bundle contains none of this code
(`test/build.test.ts` and `test/vpn-host.test.ts` check it).
