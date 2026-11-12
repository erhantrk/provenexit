import { existsSync, readFileSync } from "node:fs";
import { describe, it, expect } from "vitest";
import { checkDstackComposePolicy, PlrError } from "../src/index.js";

const DIGEST = "0123456789abcdef".repeat(4);
const IMAGE = `ghcr.io/erhantrk/provenexit-exit@sha256:${DIGEST}`;

const COMPOSE = `services:
  exit:
    image: ${IMAGE}
    restart: always
    read_only: true
    cap_drop: [ALL]
    security_opt: ["no-new-privileges:true"]
    logging:
      driver: none
    ports:
      - "18200:18200"
    volumes:
      - /var/run/dstack.sock:/var/run/dstack.sock
    environment:
      PLR_ATTESTER: dstack
      PLR_VPN_PORT: "18200"
`;

function appCompose(dockerComposeFile: string): string {
  return JSON.stringify({
    manifest_version: 2,
    name: "provenexit-exit",
    runner: "docker-compose",
    docker_compose_file: dockerComposeFile,
    kms_enabled: true,
    gateway_enabled: true,
    public_logs: false,
    public_sysinfo: false,
    allowed_envs: ["PLR_OPERATOR_KEY"],
    no_instance_id: false,
    secure_time: false,
  });
}

function code(fn: () => unknown): string {
  try {
    fn();
    return "ok";
  } catch (e) {
    return e instanceof PlrError ? e.code : "not-plr";
  }
}

const SPIKE = new URL("../../../fixtures/phala-spike/app_compose.json", import.meta.url);

describe("checkDstackComposePolicy (SPEC-TDX §1.4)", () => {
  it("accepts the SPEC-TDX §1.4 example and returns the image references", () => {
    expect(checkDstackComposePolicy(appCompose(COMPOSE))).toEqual({ images: [IMAGE] });
  });

  it("rejects an image that is not pinned by digest", () => {
    const dc = COMPOSE.replace(IMAGE, "node:22");
    expect(code(() => checkDstackComposePolicy(appCompose(dc)))).toBe("E_COMPOSE_POLICY");
    expect(() => checkDstackComposePolicy(appCompose(dc))).toThrow(PlrError);
  });

  it("rejects an exit service without logging disabled", () => {
    const dc = COMPOSE.replace("    logging:\n      driver: none\n", "");
    expect(dc).not.toContain("logging");
    expect(code(() => checkDstackComposePolicy(appCompose(dc)))).toBe("E_COMPOSE_POLICY");
  });

  it("rejects a privileged service", () => {
    const dc = COMPOSE.replace("    restart: always\n", "    restart: always\n    privileged: true\n");
    expect(code(() => checkDstackComposePolicy(appCompose(dc)))).toBe("E_COMPOSE_POLICY");
  });

  it.skipIf(!existsSync(SPIKE))("rejects the real spike S1 app-compose (unpinned image, no exit service)", () => {
    const text = readFileSync(SPIKE, "utf8");
    expect(code(() => checkDstackComposePolicy(text))).toBe("E_COMPOSE_POLICY");
  });
});
