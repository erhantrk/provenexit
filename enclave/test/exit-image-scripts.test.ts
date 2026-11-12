// scripts/build-exit-image.sh and scripts/verify-exit-image.sh, run against a fake `docker` in a throwaway git repo:
// the flags the digest depends on, the push guard, MATCH / MISMATCH. No real image is built here.
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { spawnSync } from "node:child_process";
import { chmodSync, cpSync, existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";

const ROOT = resolve(import.meta.dirname, "..", "..");
const A = "sha256:" + "a".repeat(64);
const B = "sha256:" + "b".repeat(64);
const T0 = 1700000000; // commit time of the commit that adds the image inputs

// Logs each call (one line of JSON), writes the metadata file the way buildx does, and talks on stdout.
const FAKE_DOCKER = `#!/usr/bin/env bash
node -e 'require("fs").appendFileSync(process.env.FAKE_LOG, JSON.stringify({ argv: process.argv.slice(1), epoch: process.env.SOURCE_DATE_EPOCH ?? null }) + "\\n")' -- "$@"
[ "\${FAKE_FAIL:-0}" = "1" ] && { echo "boom" >&2; exit 1; }
digest="$FAKE_DIGEST"; meta=""
while [ "$#" -gt 0 ]; do
  case "$1" in
    --metadata-file) meta="$2"; shift ;;
    --output) case "$2" in *push=true*) digest="\${FAKE_PUSH_DIGEST:-$FAKE_DIGEST}" ;; esac; shift ;;
  esac
  shift
done
echo "#1 building (stdout noise that must never reach the digest line)"
printf '{\\n  "buildx.build.ref": "x/y/z",\\n  "containerimage.descriptor": {\\n    "mediaType": "application/vnd.oci.image.manifest.v1+json",\\n    "digest": "%s",\\n    "size": 1\\n  },\\n  "containerimage.digest": "%s"\\n}' "$digest" "$digest" > "$meta"
`;

let repo: string;
let log: string;

function git(args: string[], time = T0): string {
  const r = spawnSync("git", ["-c", "user.name=t", "-c", "user.email=t@example.invalid", "-c", "commit.gpgsign=false", ...args], {
    cwd: repo, encoding: "utf8", env: { ...process.env, GIT_AUTHOR_DATE: `${time} +0000`, GIT_COMMITTER_DATE: `${time} +0000` },
  });
  if (r.status !== 0) throw new Error(`git ${args.join(" ")}: ${r.stderr}`);
  return r.stdout.trim();
}

function run(script: string, args: string[] = [], env: Record<string, string> = {}) {
  const r = spawnSync("bash", [join(repo, "scripts", script), ...args], {
    cwd: tmpdir(), encoding: "utf8",
    env: { ...process.env, PATH: `${join(repo, ".fakebin")}:${process.env.PATH}`, FAKE_LOG: log, FAKE_DIGEST: A, PUSH: "", NO_CACHE: "", BUILDER: "", IMAGE: "", TAG: "", ...env },
  });
  const calls = existsSync(log) ? readFileSync(log, "utf8").trim().split("\n").filter(Boolean).map((l) => JSON.parse(l) as { argv: string[]; epoch: string | null }) : [];
  return { status: r.status, stdout: r.stdout, stderr: r.stderr, calls };
}

const opt = (argv: string[], name: string) => argv[argv.indexOf(name) + 1] ?? "";
const pin = (digest: string) => writeFileSync(join(repo, "deploy/phala/docker-compose.yml"), `services:\n  exit:\n    image: ghcr.io/example/exit@${digest}\n    restart: always\n`);

beforeEach(() => {
  repo = mkdtempSync(join(tmpdir(), "plr-exit-image-"));
  log = join(repo, ".fakebin", "calls.log");
  mkdirSync(join(repo, ".fakebin"));
  writeFileSync(join(repo, ".fakebin", "docker"), FAKE_DOCKER);
  chmodSync(join(repo, ".fakebin", "docker"), 0o755);
  writeFileSync(join(repo, ".gitignore"), ".fakebin/\n");
  for (const f of ["scripts/exit-image-common.sh", "scripts/build-exit-image.sh", "scripts/verify-exit-image.sh", "deploy/phala/Dockerfile", "deploy/phala/Dockerfile.dockerignore"]) {
    cpSync(join(ROOT, f), join(repo, f), { recursive: true });
  }
  mkdirSync(join(repo, "enclave/src"), { recursive: true });
  mkdirSync(join(repo, "enclave/test"), { recursive: true });
  writeFileSync(join(repo, "enclave/src/x.ts"), "export const x = 1;\n");
  writeFileSync(join(repo, "enclave/test/x.test.ts"), "// test\n");
  writeFileSync(join(repo, "package.json"), "{}\n");
  writeFileSync(join(repo, "README.md"), "docs\n");
  pin(A);
  git(["init", "-q", "-b", "main"]);
  git(["add", "-A"]);
  git(["commit", "-q", "-m", "inputs"]);
});

afterEach(() => rmSync(repo, { recursive: true, force: true }));

describe("exit image scripts (fake docker)", () => {
  it("verify --print-digest prints only the digest and builds with every option the digest depends on, without pushing", () => {
    const r = run("verify-exit-image.sh", ["--print-digest"]);
    expect(r.status).toBe(0);
    expect(r.stdout).toBe(A + "\n");
    expect(r.calls).toHaveLength(1);
    const { argv, epoch } = r.calls[0]!;
    expect(argv.slice(0, 2)).toEqual(["buildx", "build"]);
    expect(opt(argv, "--platform")).toBe("linux/amd64");
    expect(argv).toContain("--provenance=false");
    expect(argv).toContain("--sbom=false");
    expect(argv).toContain("--no-cache");
    expect(opt(argv, "--build-arg")).toBe(`SOURCE_DATE_EPOCH=${T0}`);
    expect(epoch).toBe(String(T0));
    expect(opt(argv, "-f")).toBe("deploy/phala/Dockerfile");
    expect(argv[argv.length - 1]).toBe(".");
    const out = opt(argv, "--output").split(",");
    expect(out[0]).toBe("type=oci");
    expect(out).toContain("oci-mediatypes=true");
    expect(out).toContain("rewrite-timestamp=true");
    expect(out).toContain("compression=gzip");
    expect(argv.join(" ")).not.toMatch(/push/);
    expect(argv).not.toContain("--load");
  });

  it("verify prints MATCH (exit 0) when the rebuilt digest is the pinned one, MISMATCH (exit 1) otherwise", () => {
    const ok = run("verify-exit-image.sh");
    expect(ok.status).toBe(0);
    expect(ok.stdout).toContain(`built   ${A}`);
    expect(ok.stdout).toContain(`pinned  ${A}`);
    expect(ok.stdout.trimEnd().split("\n").pop()).toBe("MATCH");

    const bad = run("verify-exit-image.sh", [], { FAKE_DIGEST: B });
    expect(bad.status).toBe(1);
    expect(bad.stdout.trimEnd().split("\n").pop()).toBe("MISMATCH");
    expect(bad.stdout).not.toMatch(/^MATCH$/m);
  });

  it("verify exits 2 and prints no verdict when the build fails, the clone is shallow or the arguments are unknown", () => {
    const failed = run("verify-exit-image.sh", [], { FAKE_FAIL: "1" });
    expect(failed.status).toBe(2);
    expect(failed.stdout).not.toMatch(/MATCH/);

    expect(run("verify-exit-image.sh", ["--nope"]).status).toBe(2);

    writeFileSync(join(repo, ".git", "shallow"), git(["rev-parse", "HEAD"]) + "\n");
    const shallow = run("verify-exit-image.sh");
    expect(shallow.status).toBe(2);
    expect(shallow.stderr).toMatch(/shallow/);
    expect(shallow.stdout).not.toMatch(/MATCH/);
  });

  it("SOURCE_DATE_EPOCH follows the image inputs: unchanged by a pin, docs or test commit, changed by a source commit", () => {
    pin(B);
    writeFileSync(join(repo, "README.md"), "more docs\n");
    writeFileSync(join(repo, "enclave/test/x.test.ts"), "// test 2\n");
    git(["commit", "-q", "-am", "pin + docs + test"], T0 + 500);
    let r = run("verify-exit-image.sh", ["--print-digest"]);
    expect(r.calls.at(-1)!.epoch).toBe(String(T0));

    writeFileSync(join(repo, "enclave/src/x.ts"), "export const x = 2;\n");
    git(["commit", "-q", "-am", "source"], T0 + 900);
    r = run("verify-exit-image.sh", ["--print-digest"]);
    expect(r.calls.at(-1)!.epoch).toBe(String(T0 + 900));
  });

  it("build: no push unless PUSH=1; prints the digest", () => {
    const r = run("build-exit-image.sh");
    expect(r.status).toBe(0);
    expect(r.stdout).toBe(A + "\n");
    expect(r.calls).toHaveLength(1);
    expect(r.calls[0]!.argv.join(" ")).not.toMatch(/push/);
    expect(opt(r.calls[0]!.argv, "--output").split(",")[0]).toBe("type=oci");
  });

  it("build PUSH=1 from a clean tree: local build, then the same options with a registry output", () => {
    const r = run("build-exit-image.sh", [], { PUSH: "1", IMAGE: "registry.invalid/exit", TAG: "t1" });
    expect(r.status).toBe(0);
    expect(r.stdout).toBe(A + "\n");
    expect(r.calls).toHaveLength(2);
    const [local, push] = [r.calls[0]!.argv, r.calls[1]!.argv];
    const lo = opt(local, "--output").split(","), po = opt(push, "--output").split(",");
    expect(lo[0]).toBe("type=oci");
    expect(po.slice(0, 3)).toEqual(["type=image", "name=registry.invalid/exit:t1", "push=true"]);
    // same media types, compression and timestamps for the local digest and the pushed one
    expect(po.slice(3)).toEqual(lo.slice(2));
    for (const flag of ["--provenance=false", "--sbom=false"]) expect(push).toContain(flag);
    expect(opt(push, "--platform")).toBe("linux/amd64");
    expect(opt(push, "--build-arg")).toBe(opt(local, "--build-arg"));
  });

  it("build PUSH=1 refuses a dirty tree before running docker (untracked or modified)", () => {
    writeFileSync(join(repo, "untracked.txt"), "x\n");
    let r = run("build-exit-image.sh", [], { PUSH: "1" });
    expect(r.status).toBe(1);
    expect(r.stderr).toMatch(/dirty tree/);
    expect(r.calls).toHaveLength(0);
    rmSync(join(repo, "untracked.txt"));

    writeFileSync(join(repo, "README.md"), "edited\n");
    r = run("build-exit-image.sh", [], { PUSH: "1" });
    expect(r.status).toBe(1);
    expect(r.calls).toHaveLength(0);
  });

  it("build PUSH=1 fails when the registry digest differs from the local one", () => {
    const r = run("build-exit-image.sh", [], { PUSH: "1", FAKE_PUSH_DIGEST: B });
    expect(r.status).toBe(1);
    expect(r.stderr).toMatch(/differs/);
    expect(r.stdout).toBe("");
  });

  it("a dirty image input is reported on stderr (the digest is then not a commit's)", () => {
    writeFileSync(join(repo, "enclave/src/x.ts"), "export const x = 3;\n");
    const r = run("verify-exit-image.sh", ["--print-digest"]);
    expect(r.stdout).toBe(A + "\n");
    expect(r.stderr).toMatch(/WARNING: uncommitted changes in the image inputs/);
  });
});

describe("exit image inputs", () => {
  const ignore = readFileSync(join(ROOT, "deploy/phala/Dockerfile.dockerignore"), "utf8").split("\n").map((l) => l.trim()).filter((l) => l && !l.startsWith("#"));
  const common = readFileSync(join(ROOT, "scripts/exit-image-common.sh"), "utf8");
  const inputs = /EXIT_IMAGE_INPUTS=\(\n([\s\S]*?)\n\)/.exec(common)![1]!.split("\n").map((l) => l.trim().replace(/^'(.*)'$/, "$1"));

  it("the dockerignore lets in exactly the inputs SOURCE_DATE_EPOCH is computed from", () => {
    expect(ignore[0]).toBe("*");
    const allowed = ignore.filter((l) => l.startsWith("!")).map((l) => l.slice(1));
    const dockerfiles = ["deploy/phala/Dockerfile", "deploy/phala/Dockerfile.dockerignore"];
    expect(inputs.filter((i) => !i.startsWith(":(exclude)"))).toEqual([...dockerfiles, ...allowed]);
    const excluded = inputs.filter((i) => i.startsWith(":(exclude)")).map((i) => i.slice(":(exclude)".length));
    expect(excluded).toEqual(["enclave/test", "packages/shared/test"]);
    for (const e of excluded) expect(ignore).toContain(e);
  });

  it("the Dockerfile copies nothing from outside the allowed inputs, pins one base by digest and has no syntax line", () => {
    const df = readFileSync(join(ROOT, "deploy/phala/Dockerfile"), "utf8");
    const allowed = ignore.filter((l) => l.startsWith("!")).map((l) => l.slice(1));
    const copies = df.split("\n").filter((l) => /^COPY /.test(l) && !l.includes("--from="));
    expect(copies.length).toBeGreaterThan(0);
    for (const line of copies) {
      const srcs = line.split(/\s+/).slice(1, -1);
      for (const s of srcs) expect(allowed.some((a) => s === a || s.startsWith(a + "/")), line).toBe(true);
    }
    const froms = df.split("\n").filter((l) => /^FROM /.test(l)).map((l) => l.split(/\s+/)[1]);
    expect(froms).toHaveLength(2);
    expect(new Set(froms).size).toBe(1);
    expect(froms[0]).toMatch(/^node:22-bookworm-slim@sha256:[0-9a-f]{64}$/);
    expect(df).not.toMatch(/^#\s*syntax\s*=/m);
    expect(df).toMatch(/npm ci --ignore-scripts/);
  });
});
