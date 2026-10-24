# Local Solana facts (verified 2026-10-24 on this machine)
- Agave CLI 4.3.1: PATH must include /Users/exampleuser/.local/share/solana/install/active_release/bin
  (solana, solana-keygen, solana-test-validator, cargo-build-sbf). SBF platform tools are cached (~/.cache/solana).
- Validator: `solana-test-validator --ledger <dir> --rpc-port <p> --faucet-port <f> --quiet --reset` → RPC up in ~2 s.
  Airdrop works (`solana -u http://127.0.0.1:<p> airdrop 10 <pubkey>`); `solana program deploy <so> --keypair <kp>` works.
- Feature SIMD-0075 (secp256r1 precompile) is active from epoch 0 on the test validator; the ed25519 precompile is standard.
- Program crate: solana-program = "=5.1.0" (cached), crate-type ["cdylib","lib"]; build `cargo-build-sbf` → target/deploy/<name>.so.
- JS: @solana/web3.js 1.99.0 installed in client/enclave/e2e workspaces.
