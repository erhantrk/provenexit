// Rebuilds the local preview fixtures. Run from site/: `npm run fixtures`.
//   online.json           status/sample-online.json, unchanged (exit running, verified)
//   offline-retired.json  status/sample-offline.json, unchanged (exit stopped, retired registry)
//   offline.json          exit stopped on the current registry: the stopped-exit fields of the
//                         real offline sample over the chain facts of the real online sample
//   refused.json          the online sample after an owner revoke, following getStatus():
//                         the first failing check carries the code, later checks are
//                         "not checked", exit.compose and exit.egress_ip are null
//   error.json            getStatus() run against closed loopback ports (no outside request)
import { readFileSync, writeFileSync } from "node:fs";
import { getStatus } from "../api/_lib/provenexit-status.mjs";

const here = new URL(".", import.meta.url);
const read = (p) => JSON.parse(readFileSync(new URL(p, here), "utf8"));
const write = (name, v) => writeFileSync(new URL(name, here), JSON.stringify(v, null, 2) + "\n");

const online = read("../../status/sample-online.json");
const retired = read("../../status/sample-offline.json");
write("online.json", online);
write("offline-retired.json", retired);

const offline = structuredClone(online);
offline.exit = { ...online.exit, online: false, egress_ip: null, compose: null };
offline.verify = structuredClone(retired.verify);
write("offline.json", offline);

const CODE = "E_COMPOSE_NOT_ALLOWED";
const refused = structuredClone(online);
const at = refused.verify.checks.findIndex((c) => c.name === "compose hash allowed by registry");
refused.verify.verdict = "REFUSED";
refused.verify.code = CODE;
refused.verify.checks = refused.verify.checks.map((c, i) =>
  i < at ? c : i === at ? { ...c, ok: false, detail: CODE } : { ...c, ok: false, detail: "not checked" });
refused.exit.compose = null;
refused.exit.egress_ip = null;
refused.registry.events.unshift({
  kind: "revoke_compose",
  hash: online.exit.compose.hash,
  account: null,
  org: null,
  tx: "SampleRevokeNotOnChain11111111111111111111111",
  // 30 s after the online sample's check, so it is always the newest event for that hash.
  at: new Date(Date.parse(online.checked_at) + 30_000).toISOString(),
});
write("refused.json", refused);

const dead = "http://127.0.0.1:9";
const error = await getStatus({
  exitUrl: dead, rpcUrl: dead, nearBlocksApi: dead, archivalRpc: dead, egress: null,
  timeouts: { healthz: 1500, verify: 4000, egress: 1000, chain: 1500, events: 1500 },
});
error.exit.url = online.exit.url;
error.checked_at = "2026-11-12T18:33:00.000Z";
write("error.json", error);
process.exit(0);
