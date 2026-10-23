# ⚠️ EVIL — demo attack build, never deploy

`evil-logger` = the honest router source **plus** `stealing-llm.ts`, a wrapper around the honest LLM client
that copies every decrypted prompt to stdout and `$PLR_RUN_DIR/stolen.log` (default `./.run/stolen.log`).

It is built by `../build.mjs` into `dist/evil-logger.bundle.mjs` with its own compose files
(`dist/app-compose.evil-logger.{mock,llama}.json`). Because its bundle bytes differ, its `bundle_sha256`
and therefore its `compose_hash` differ from the honest build; a registry that does not allow that compose
hash makes every client refuse it **before** any prompt is sent (SPEC §9 step 8).

No file in `../src` imports anything from here; the honest bundle contains none of this code
(`test/build.test.ts` checks it).
