# Local Stellar facts (verified 2026-10-24 on this machine)
- stellar CLI 27.1.0 at /opt/homebrew/bin/stellar; Docker Desktop running; image stellar/quickstart:latest (RPC 30.0.0).
- Start: `stellar container start local --name <n> -p <port>:8000 --protocol-version 29 --limits unlimited`
  (default protocol 28 makes every Soroban simulation fail with `HostError: Error(Context, InternalError)` for SDK 29 wasm).
  Container name becomes `stellar-<n>`. Wait for RPC `getHealth` = healthy, then ~20 s more before friendbot funding works.
  Stop: `stellar container stop <n>`.
- RPC: http://localhost:<port>/rpc, passphrase "Standalone Network ; February 2017", friendbot http://localhost:<port>/friendbot.
- `stellar network add <name> --rpc-url … --network-passphrase …`; `stellar keys generate <k> --network <name> --fund`.
- Rust: soroban-sdk = "=29.0.1" (testutils in dev-deps) — crates are pre-fetched in ~/.cargo; build with `stellar contract build`
  → target/wasm32v1-none/release/<crate>.wasm. Release profile MUST have overflow-checks = true (CLI refuses otherwise):
  opt-level "z", overflow-checks true, debug 0, strip "symbols", panic "abort", codegen-units 1, lto true.
- Verified: deploy + invoke of a contract calling env.crypto().sha256 returned sha256("abc") correctly.
- JS: @stellar/stellar-sdk 17.3.0 installed in client/enclave/e2e workspaces.
