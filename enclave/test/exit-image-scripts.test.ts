// scripts/build-exit-image.sh and scripts/verify-exit-image.sh, run against a fake `docker` in a throwaway git repo:
// the flags the digest depends on, the push guard, MATCH / MISMATCH. No real image is built here.
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { chmodSync, cpSync, existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";

const ROOT = resolve(import.meta.dirname, "..", "..");
const A = "sha256:" + "a".repeat(64);
const B = "sha256:" + "b".repeat(64);
const T0 = 1700000000; // commit time of the commit that adds the image inputs
const COMMON = readFileSync(join(ROOT, "scripts/exit-image-common.sh"), "utf8");
const shVar = (name: string) => new RegExp(`^${name}=(\\S+)$`, "m").exec(COMMON)![1]!;
const EPOCH = shVar("EXIT_IMAGE_EPOCH");
const BUILDKIT_VERSION = shVar("EXIT_IMAGE_BUILDKIT_VERSION");
const BUILDKIT_IMAGE = shVar("EXIT_IMAGE_BUILDKIT_IMAGE");
const PINNED_BUILDER = shVar("EXIT_IMAGE_BUILDER");

// Logs each call (one line of JSON) and talks on stdout. Builders are files in .fakebin/builders: `buildx inspect`
// fails for a missing one, `buildx create` adds one, `inspect --bootstrap` reports a BuildKit version. `buildx build`
// writes the metadata file the way buildx does; `imagetools inspect --raw` prints the raw document the tag resolves to:
// FAKE_TAG_RAW if set, else an OCI image index that lists one manifest (FAKE_TAG_DIGEST, default the built digest),
// which is what `imagetools create` stored for the real push.
const FAKE_DOCKER = `#!/usr/bin/env bash
node -e 'require("fs").appendFileSync(process.env.FAKE_LOG, JSON.stringify({ argv: process.argv.slice(1), epoch: process.env.SOURCE_DATE_EPOCH ?? null }) + "\\n")' -- "$@"
builders="$(dirname "$FAKE_LOG")/builders"; mkdir -p "$builders"
last="\${!#}"
case "$1 $2" in
  "buildx inspect")
    [ -e "$builders/$last" ] || { echo "ERROR: no builder \\"$last\\" found" >&2; exit 1; }
    printf 'Name:          %s\\nDriver:        docker-container\\n\\nNodes:\\nName:             %s0\\nStatus:           running\\nBuildKit version: %s\\nPlatforms:        linux/amd64\\n' "$last" "$last" "$FAKE_BUILDKIT"
    exit 0 ;;
  "buildx create")
    [ "\${FAKE_CREATE_FAIL:-0}" = "1" ] && { echo "cannot create" >&2; exit 1; }
    while [ "$#" -gt 0 ]; do [ "$1" = "--name" ] && : > "$builders/$2"; shift; done
    echo "created (stdout noise)"; exit 0 ;;
  "buildx imagetools")
    case "$3" in
      create) [ "\${FAKE_TAG_FAIL:-0}" = "1" ] && { echo "denied" >&2; exit 1; }; echo "tagged (stdout noise)"; exit 0 ;;
      inspect)
        case " $* " in *" --raw "*) ;; *) echo "fake docker: imagetools inspect without --raw" >&2; exit 1 ;; esac
        [ "\${FAKE_INSPECT_FAIL:-0}" = "1" ] && { echo "not found" >&2; exit 1; }
        if [ -n "\${FAKE_TAG_RAW:-}" ]; then printf '%s' "$FAKE_TAG_RAW"; else printf '%s' "$(node -e 'process.stdout.write(process.env.FAKE_INDEX.replace("DIGEST", process.argv[1]))' "\${FAKE_TAG_DIGEST:-$FAKE_DIGEST}")"; fi
        exit 0 ;;
    esac
    exit 1 ;;
  "buildx build") ;;
  *) echo "fake docker: unexpected $*" >&2; exit 1 ;;
esac
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

// The raw index a tag resolves to (DIGEST is replaced), and a raw image manifest, as a registry serves them.
const INDEX = `{\n  "schemaVersion": 2,\n  "mediaType": "application/vnd.oci.image.index.v1+json",\n  "manifests": [\n    {\n      "mediaType": "application/vnd.oci.image.manifest.v1+json",\n      "digest": "DIGEST",\n      "size": 2065,\n      "platform": {\n        "architecture": "amd64",\n        "os": "linux"\n      }\n    }\n  ]\n}`;
const MANIFEST = `{"schemaVersion":2,"mediaType":"application/vnd.oci.image.manifest.v1+json","config":{"mediaType":"application/vnd.oci.image.config.v1+json","digest":"sha256:${"c".repeat(64)}","size":1},"layers":[{"mediaType":"application/vnd.oci.image.layer.v1.tar+gzip","digest":"sha256:${"d".repeat(64)}","size":1}]}`;
const digestOf = (raw: string) => "sha256:" + createHash("sha256").update(raw).digest("hex");

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
    env: { ...process.env, PATH: `${join(repo, ".fakebin")}:${process.env.PATH}`, FAKE_LOG: log, FAKE_DIGEST: A, FAKE_BUILDKIT: BUILDKIT_VERSION, FAKE_INDEX: INDEX, FAKE_TAG_RAW: "", PUSH: "", NO_CACHE: "", BUILDER: "", IMAGE: "", TAG: "", ...env },
  });
  const calls = existsSync(log) ? readFileSync(log, "utf8").trim().split("\n").filter(Boolean).map((l) => JSON.parse(l) as { argv: string[]; epoch: string | null }) : [];
  // `builds` are the `docker buildx build` calls; `calls` is every docker call, in order
  return { status: r.status, stdout: r.stdout, stderr: r.stderr, calls, builds: calls.filter((c) => c.argv[1] === "build") };
}
const sub = (calls: { argv: string[] }[], ...words: string[]) => calls.filter((c) => words.every((w, i) => c.argv[i] === w));

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
    expect(r.builds).toHaveLength(1);
    const { argv, epoch } = r.builds[0]!;
    expect(argv.slice(0, 2)).toEqual(["buildx", "build"]);
    expect(opt(argv, "--builder")).toBe(PINNED_BUILDER);
    expect(opt(argv, "--platform")).toBe("linux/amd64");
    expect(argv).toContain("--provenance=false");
    expect(argv).toContain("--sbom=false");
    expect(argv).toContain("--no-cache");
    expect(opt(argv, "--build-arg")).toBe(`SOURCE_DATE_EPOCH=${EPOCH}`);
    expect(epoch).toBe(EPOCH);
    expect(opt(argv, "-f")).toBe("deploy/phala/Dockerfile");
    expect(argv[argv.length - 1]).toBe(".");
    const out = opt(argv, "--output").split(",");
    expect(out[0]).toBe("type=oci");
    expect(out).toContain("oci-mediatypes=true");
    expect(out).toContain("rewrite-timestamp=true");
    expect(out).toContain("compression=gzip");
    expect(argv.join(" ")).not.toMatch(/push/);
    expect(argv).not.toContain("--load");
    expect(r.calls.some((c) => c.argv.includes("imagetools"))).toBe(false);
  });

  it("verify prints MATCH (exit 0) when the rebuilt digest is the pinned one, MISMATCH (exit 1) otherwise", () => {
    const ok = run("verify-exit-image.sh");
    expect(ok.status).toBe(0);
    expect(ok.stdout).toContain(`builder ${PINNED_BUILDER} (BuildKit ${BUILDKIT_VERSION})`);
    expect(ok.stdout).toContain(`built   ${A}`);
    expect(ok.stdout).toContain(`pinned  ${A}`);
    expect(ok.stdout.trimEnd().split("\n").pop()).toBe("MATCH");

    const bad = run("verify-exit-image.sh", [], { FAKE_DIGEST: B });
    expect(bad.status).toBe(1);
    expect(bad.stdout.trimEnd().split("\n").pop()).toBe("MISMATCH");
    expect(bad.stdout).not.toMatch(/^MATCH$/m);
  });

  it("verify exits 2 and prints no verdict when the build fails, the builder cannot be made or the arguments are unknown", () => {
    // first: no builder exists yet in this repo, so it has to be created
    const noBuilder = run("verify-exit-image.sh", [], { FAKE_CREATE_FAIL: "1" });
    expect(noBuilder.status).toBe(2);
    expect(noBuilder.stderr).toMatch(/could not create the pinned builder/);
    expect(noBuilder.stdout).not.toMatch(/MATCH/);
    expect(noBuilder.builds).toHaveLength(0);

    const failed = run("verify-exit-image.sh", [], { FAKE_FAIL: "1" });
    expect(failed.status).toBe(2);
    expect(failed.stdout).not.toMatch(/MATCH/);

    expect(run("verify-exit-image.sh", ["--nope"]).status).toBe(2);
  });

  it("the default builder is the docker-container builder pinned by digest: created once, started, its BuildKit version checked", () => {
    expect(BUILDKIT_IMAGE).toMatch(/^moby\/buildkit:v\d+\.\d+\.\d+@sha256:[0-9a-f]{64}$/);
    expect(BUILDKIT_IMAGE.startsWith(`moby/buildkit:${BUILDKIT_VERSION}@sha256:`)).toBe(true);
    // the builder name carries the pin (version + start of the digest), so a new pin never reuses an old builder
    expect(PINNED_BUILDER).toContain(BUILDKIT_VERSION);
    expect(PINNED_BUILDER.endsWith(BUILDKIT_IMAGE.split("@sha256:")[1]!.slice(0, 12))).toBe(true);

    let r = run("verify-exit-image.sh", ["--print-digest"]);
    expect(r.status).toBe(0);
    const created = sub(r.calls, "buildx", "create");
    expect(created).toHaveLength(1);
    expect(opt(created[0]!.argv, "--name")).toBe(PINNED_BUILDER);
    expect(opt(created[0]!.argv, "--driver")).toBe("docker-container");
    expect(opt(created[0]!.argv, "--driver-opt")).toBe(`image=${BUILDKIT_IMAGE}`);
    expect(created[0]!.argv).not.toContain("--use"); // the user's current builder is left alone
    expect(sub(r.calls, "buildx", "inspect", "--bootstrap").map((c) => c.argv.at(-1))).toEqual([PINNED_BUILDER]);
    expect(r.calls.findIndex((c) => c.argv[1] === "create")).toBeLessThan(r.calls.findIndex((c) => c.argv[1] === "build"));
    expect(r.stderr).toContain(`builder ${PINNED_BUILDER}, BuildKit ${BUILDKIT_VERSION}`);
    expect(r.stdout).toBe(A + "\n");

    // second run: the builder exists and is reused
    r = run("verify-exit-image.sh", ["--print-digest"]);
    expect(r.status).toBe(0);
    expect(sub(r.calls, "buildx", "create")).toHaveLength(1);
    expect(r.builds).toHaveLength(2);

    // a builder of that name that runs another BuildKit is refused: no build, no verdict
    r = run("verify-exit-image.sh", [], { FAKE_BUILDKIT: "v0.1.0" });
    expect(r.status).toBe(2);
    expect(r.stderr).toMatch(/runs BuildKit v0\.1\.0, not the pinned/);
    expect(r.stdout).not.toMatch(/MATCH/);
    expect(r.builds).toHaveLength(2);
  });

  it("BUILDER=<name> uses that builder, creates none, and warns that it is not the pinned one", () => {
    mkdirSync(join(repo, ".fakebin", "builders"));
    writeFileSync(join(repo, ".fakebin", "builders", "mine"), "");
    const r = run("verify-exit-image.sh", [], { BUILDER: "mine", FAKE_BUILDKIT: "v0.1.0" });
    expect(r.status).toBe(0);
    expect(sub(r.calls, "buildx", "create")).toHaveLength(0);
    expect(opt(r.builds[0]!.argv, "--builder")).toBe("mine");
    expect(r.stderr).toMatch(/WARNING: BUILDER=mine \(BuildKit v0\.1\.0\) is not the pinned builder/);
    expect(r.stdout).toContain("builder mine (BuildKit v0.1.0)");

    const missing = run("verify-exit-image.sh", [], { BUILDER: "nope" });
    expect(missing.status).toBe(2);
    expect(missing.stdout).not.toMatch(/MATCH/);
  });

  it("SOURCE_DATE_EPOCH is a constant: the same after a source commit at another time, after an amend (a rebase) and in a shallow clone", () => {
    expect(EPOCH).toMatch(/^[0-9]+$/);
    expect(COMMON).not.toMatch(/git log|%ct|is-shallow/); // no commit time, no history lookup
    const epochOfBuild = () => {
      const r = run("verify-exit-image.sh", ["--print-digest"]);
      expect(r.status).toBe(0);
      expect(r.builds.at(-1)!.epoch).toBe(EPOCH);
      expect(opt(r.builds.at(-1)!.argv, "--build-arg")).toBe(`SOURCE_DATE_EPOCH=${EPOCH}`);
    };
    epochOfBuild();

    writeFileSync(join(repo, "enclave/src/x.ts"), "export const x = 2;\n");
    writeFileSync(join(repo, "README.md"), "more docs\n");
    git(["commit", "-q", "-am", "source + docs"], T0 + 900);
    epochOfBuild();

    // the same tree under a new commit (what a rebase or a squash-merge does): new committer time, same epoch
    const tree = git(["rev-parse", "HEAD^{tree}"]);
    git(["commit", "-q", "--amend", "-m", "squashed"], T0 + 5000);
    expect(git(["rev-parse", "HEAD^{tree}"])).toBe(tree);
    expect(git(["log", "-1", "--format=%ct"])).toBe(String(T0 + 5000));
    epochOfBuild();

    writeFileSync(join(repo, ".git", "shallow"), git(["rev-parse", "HEAD"]) + "\n");
    expect(git(["rev-parse", "--is-shallow-repository"])).toBe("true");
    epochOfBuild();
    const shallow = run("verify-exit-image.sh");
    expect(shallow.status).toBe(0);
    expect(shallow.stdout.trimEnd().split("\n").pop()).toBe("MATCH");
  });

  it("build: no push unless PUSH=1; prints the digest", () => {
    const r = run("build-exit-image.sh");
    expect(r.status).toBe(0);
    expect(r.stdout).toBe(A + "\n");
    expect(r.builds).toHaveLength(1);
    expect(r.builds[0]!.argv.join(" ")).not.toMatch(/push/);
    expect(opt(r.builds[0]!.argv, "--output").split(",")[0]).toBe("type=oci");
    expect(r.calls.some((c) => c.argv.includes("imagetools"))).toBe(false);
    expect(r.stderr).toContain(`builder ${PINNED_BUILDER} (BuildKit ${BUILDKIT_VERSION})`);
  });

  it("build PUSH=1 from a clean tree: local build, then the same options pushed by digest without a tag, then the tag", () => {
    const r = run("build-exit-image.sh", [], { PUSH: "1", IMAGE: "registry.invalid/exit", TAG: "t1" });
    expect(r.status).toBe(0);
    expect(r.stdout).toBe(A + "\n");
    expect(r.builds).toHaveLength(2);
    const [local, push] = [r.builds[0]!.argv, r.builds[1]!.argv];
    const lo = opt(local, "--output").split(","), po = opt(push, "--output").split(",");
    expect(lo[0]).toBe("type=oci");
    // the build uploads by digest only: its output names the repository, never a tag
    expect(po.slice(0, 4)).toEqual(["type=image", "name=registry.invalid/exit", "push-by-digest=true", "push=true"]);
    expect(push.join(" ")).not.toContain("registry.invalid/exit:t1");
    // same media types, compression and timestamps for the local digest and the pushed one
    expect(po.slice(4)).toEqual(lo.slice(2));
    for (const flag of ["--provenance=false", "--sbom=false"]) expect(push).toContain(flag);
    expect(opt(push, "--platform")).toBe("linux/amd64");
    expect(opt(push, "--build-arg")).toBe(opt(local, "--build-arg"));
    expect(opt(push, "--builder")).toBe(opt(local, "--builder"));
    // the tag is added to the verified digest, after both builds, and then read back
    const tag = sub(r.calls, "buildx", "imagetools", "create");
    expect(tag).toHaveLength(1);
    expect(opt(tag[0]!.argv, "-t")).toBe("registry.invalid/exit:t1");
    expect(tag[0]!.argv.at(-1)).toBe(`registry.invalid/exit@${A}`);
    expect(r.calls.indexOf(tag[0]!)).toBeGreaterThan(r.calls.indexOf(r.builds[1]!));
    const back = sub(r.calls, "buildx", "imagetools", "inspect");
    expect(back).toHaveLength(1);
    expect(back[0]!.argv.at(-1)).toBe("registry.invalid/exit:t1");
    expect(back[0]!.argv).toContain("--raw");
    expect(r.calls.indexOf(back[0]!)).toBeGreaterThan(r.calls.indexOf(tag[0]!));
  });

  it("build PUSH=1 reports what the tag resolves to: an index digest that wraps the manifest, or the manifest itself", () => {
    // the tag is an image index listing only the pushed manifest: both digests are reported, never "tag = manifest digest"
    let r = run("build-exit-image.sh", [], { PUSH: "1", IMAGE: "registry.invalid/exit", TAG: "t1" });
    const index = digestOf(INDEX.replace("DIGEST", A));
    expect(index).not.toBe(A);
    expect(r.status).toBe(0);
    expect(r.stdout).toBe(A + "\n");
    expect(r.stderr).toContain(`pushed registry.invalid/exit@${A} (image manifest, linux/amd64)`);
    expect(r.stderr).toContain(`tag registry.invalid/exit:t1 -> image index ${index}, which lists only that manifest`);
    expect(r.stderr).not.toMatch(/exit:t1 = /);
    expect(r.stderr).not.toContain(`exit:t1 -> ${A}`);

    // the tag is the manifest itself (its raw bytes hash to the built digest)
    const m = digestOf(MANIFEST);
    r = run("build-exit-image.sh", [], { PUSH: "1", IMAGE: "registry.invalid/exit", TAG: "t1", FAKE_DIGEST: m, FAKE_TAG_RAW: MANIFEST });
    expect(r.status).toBe(0);
    expect(r.stdout).toBe(m + "\n");
    expect(r.stderr).toContain(`tag registry.invalid/exit:t1 -> ${m} (that manifest)`);
    expect(r.stderr).not.toMatch(/image index/);
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

  it("build PUSH=1 fails when the registry digest differs from the local one, and then creates no tag", () => {
    const r = run("build-exit-image.sh", [], { PUSH: "1", IMAGE: "registry.invalid/exit", TAG: "t1", FAKE_PUSH_DIGEST: B });
    expect(r.status).toBe(1);
    expect(r.stderr).toMatch(/differs/);
    expect(r.stdout).toBe("");
    expect(r.calls.some((c) => c.argv.includes("imagetools"))).toBe(false);
    expect(r.calls.some((c) => c.argv.join(" ").includes("registry.invalid/exit:t1"))).toBe(false);
  });

  it("build PUSH=1 fails when the tag cannot be created or does not resolve to the local digest", () => {
    let r = run("build-exit-image.sh", [], { PUSH: "1", FAKE_TAG_FAIL: "1" });
    expect(r.status).toBe(1);
    expect(r.stderr).toMatch(/tagging it .* failed/);
    expect(r.stdout).toBe("");

    // an index that lists another manifest
    r = run("build-exit-image.sh", [], { PUSH: "1", FAKE_TAG_DIGEST: B });
    expect(r.status).toBe(1);
    expect(r.stderr).toMatch(/do not deploy by tag/);
    expect(r.stdout).toBe("");

    // an index that lists the manifest and something else, another manifest, an unreadable tag
    const two = INDEX.replace("DIGEST", A).replace(/\n  \]\n\}$/, `,\n    {\n      "mediaType": "application/vnd.oci.image.manifest.v1+json",\n      "digest": "${B}",\n      "size": 1\n    }\n  ]\n}`);
    expect(two).toContain(A);
    expect(two).toContain(B);
    for (const env of [{ FAKE_TAG_RAW: two }, { FAKE_TAG_RAW: MANIFEST }, { FAKE_INSPECT_FAIL: "1" }]) {
      r = run("build-exit-image.sh", [], { PUSH: "1", ...env });
      expect(r.status).toBe(1);
      expect(r.stderr).toMatch(/do not deploy by tag/);
      expect(r.stdout).toBe("");
    }
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
  const inputs = /EXIT_IMAGE_INPUTS=\(\n([\s\S]*?)\n\)/.exec(COMMON)![1]!.split("\n").map((l) => l.trim().replace(/^'(.*)'$/, "$1"));

  it("the dockerignore lets in exactly the inputs the scripts treat as image inputs", () => {
    expect(ignore[0]).toBe("*");
    const allowed = ignore.filter((l) => l.startsWith("!")).map((l) => l.slice(1));
    const dockerfiles = ["deploy/phala/Dockerfile", "deploy/phala/Dockerfile.dockerignore"];
    expect(inputs.filter((i) => !i.startsWith(":(exclude)"))).toEqual([...dockerfiles, ...allowed]);
    const excluded = inputs.filter((i) => i.startsWith(":(exclude)")).map((i) => i.slice(":(exclude)".length));
    expect(excluded).toEqual(["enclave/test", "packages/shared/test"]);
    for (const e of excluded) expect(ignore).toContain(e);
  });

  it("the README names the pinned BuildKit image and the constant epoch the scripts use", () => {
    const readme = readFileSync(join(ROOT, "deploy/phala/README.md"), "utf8");
    expect(readme).toContain(BUILDKIT_IMAGE);
    expect(readme).toContain(`SOURCE_DATE_EPOCH=${EPOCH}`);
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
