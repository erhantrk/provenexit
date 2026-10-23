# PLR-COMBO — LLM router and VPN exit in one TEE

Status: **FROZEN** (2026-10-23). Builds on `SPEC.md` rev 1.3 and `SPEC-VPN.md` rev 2. Purpose: a single confidential VM
(e.g. one Azure DC2es_v5) runs both services for a low-cost demo. Clients are unchanged: they verify each service exactly as
before; the measured compose simply describes both services.

## 1. Compose (`name: "plr-combo"`)
Canonical form and hashing as SPEC §4. Exact keys:
```json
{
  "manifest_version": 1,
  "name": "plr-combo",
  "router": {
    "bundle_sha256": "<64 hex>", "entry": "router.bundle.mjs", "node_sha256": "<64 hex>",
    "llm": { "kind": "llama.cpp" | "mock", "model_sha256": "<64 hex>", "runtime": "<string>", "runtime_sha256": "<64 hex>" },
    "policy": { "disk": "none", "egress": [], "logs": "none" }
  },
  "vpn": {
    "bundle_sha256": "<64 hex>", "entry": "vpn.bundle.mjs", "node_sha256": "<64 hex>",
    "policy": { "disk": "none", "dns": { "doh": [ … ] }, "egress": { "allow_loopback": false, "deny_private": true }, "logs": "none" }
  }
}
```
Field rules are those of the router compose (SPEC §4 rev 1.1) and the VPN compose (SPEC-VPN §2 rev 2) respectively.
`router.node_sha256 == vpn.node_sha256` (one runtime). For `llm.kind == "mock"`, `llm.runtime_sha256 == router.node_sha256`.

Builds (`enclave/build.mjs`, recorded under a `combo` key in `build-info.json`): `combo` (production VPN policy and DoH list)
and `combo-test` (VPN test policy: `allow_loopback: true`, DoH `http://127.0.0.1:18253/dns-query`), each for llm kinds
`mock` and `llama.cpp`.

## 2. Launch (mock TDX host)
For a `plr-combo` compose the host measures the router bundle, the VPN bundle, the model / mock LLM and the runtime(s),
refuses on any mismatch, extends RTMR3 once with the boot sequence for this compose, then starts **three separate
processes**: the LLM, the router and the VPN exit. Each runs with the existing isolation (read-only fs, no child processes,
no addons, no code generation from strings) and its own environment allowlist: the router gets the LLM port + per-boot LLM
API key and the LLM registry settings; the exit gets the VPN registry settings and **no** LLM port or key. Router and exit
listen on separate ports (defaults 18100 / 18200) and print their usual `listening` lines. One quote socket serves both.

Each service generates its own keys at boot (distinct `key_hash`), registers on its own registry (router → `PLR_REGISTRY`,
exit → `PLR_VPN_REGISTRY`, both rev 1.3 operator-bound) and anchors its own receipts. Both `/v1/attestation` bundles carry
the same combo `app_compose`.

## 3. Policy and trust
- Approval is per registry: the owner allows the combo compose hash (and OS measurement) on the LLM registry to approve the
  router role, and on the VPN registry to approve the exit role. Approving one does not approve the other.
- Because one measurement covers both programs, any change to either changes the compose hash (re-approval needed).
- Isolation boundary: separate processes in one TD. They share the TD's memory encryption domain, so a defect in one
  service is not cryptographically contained from the other (documented trade-off for the demo). The exit cannot reach the
  router or LLM over the network in production (`allow_loopback: false`, private ranges denied), and the LLM requires the
  per-boot key that only the router receives.

## 4. Harness additions (`e2e/src/harness.ts`)
```ts
type ComboVariant = "combo" | "combo-test";
interface Stack { …
  approveComboBuild(v: ComboVariant, o?: { llm?: boolean; vpn?: boolean }): Promise<{ composeHash: string; osMeasurement: string }>; // default both
  startCombo(v: ComboVariant, o?: { register?: boolean; operator?: "operator" | "operator2" }): Promise<ComboHandle>;
}
interface ComboHandle { routerUrl: string; vpnUrl: string; composeHash: string; routerKeyHash: string; vpnKeyHash: string;
                        routerPort: number; output(): string; stop(): Promise<void> }
```
Combo builds use the stack's LLM choice (`mock` in tests). `output()` = host + LLM + router + exit stdout/stderr.
