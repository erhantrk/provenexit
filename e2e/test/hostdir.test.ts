// Host socket directory: any clone path / run root must yield a usable (<= 103 byte) Unix socket path.
import { describe, it, expect } from "vitest";
import { createServer } from "node:net";
import { mkdirSync, rmSync, statSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { hostDirCandidates, hostDirFor } from "../src/harness.js";

const SUFFIX = "/tdx-XXXXXX/q.sock";
const sockLen = (dir: string): number => Buffer.byteLength(dir + SUFFIX);

describe("hostDirFor", () => {
  it("keeps the host dir next to the run dir when the socket path fits", () => {
    expect(hostDirFor("/r/.run", "demo-1794418575-extra")).toBe("/r/.run/demo-1794418575-extra-host");
  });

  it("fits exactly at the limit (103 bytes) and moves out one byte later", () => {
    const id = "demo-1794418575-extra"; // 21 bytes, longer than any demo.sh id
    const fixed = `/${id}-host`.length + SUFFIX.length;
    const okRoot = "/" + "a".repeat(103 - fixed - 1);
    expect(sockLen(hostDirFor(okRoot, id))).toBe(103);
    expect(hostDirFor(okRoot, id)).toBe(`${okRoot}/${id}-host`);
    const tooLong = okRoot + "a";
    const moved = hostDirFor(tooLong, id);
    expect(moved).not.toBe(`${tooLong}/${id}-host`);
    expect(sockLen(moved)).toBeLessThanOrEqual(103);
  });

  it("candidates: id dir, then a short hash dir in the root, then the tmp bases; all fit", () => {
    const root = "/Users/exampleuser/personal/web3/hackathons/provenexit/.run";
    const c = hostDirCandidates(root, "demo-1794418575-extra", ["/tmp", "relative", "/" + "t".repeat(120)]);
    expect(c).toHaveLength(2); // the id dir is 104 bytes (does not fit), "relative" and the long base are dropped
    expect(c[0]!.startsWith(`${root}/plr-`)).toBe(true);
    expect(c[1]!.startsWith("/tmp/plr-")).toBe(true);
    expect(c.every((d) => sockLen(d) <= 103)).toBe(true);
    expect(hostDirCandidates("/r/.run", "x", ["/tmp"])).toEqual(["/r/.run/x-host", expect.stringMatching(/^\/r\/\.run\/plr-[0-9a-f]{12}$/), expect.stringMatching(/^\/tmp\/plr-[0-9a-f]{12}$/)]);
  });

  it("a 59-byte root (this checkout's `.run`) with a 21-byte demo id stays usable", () => {
    const root = "/Users/exampleuser/personal/web3/hackathons/provenexit/.run";
    expect(Buffer.byteLength(root)).toBe(59);
    expect(sockLen(hostDirFor(root, "demo-1794418575-extra"))).toBeLessThanOrEqual(103);
  });

  it("a very long clone path falls back to a short, deterministic, per-run directory", () => {
    const root = "/Users/someone/" + "very-long-directory-name/".repeat(8) + "provenexit/.run";
    expect(hostDirCandidates(root, "e2e-abc-123456", ["/tmp"])).toEqual([expect.stringMatching(/^\/tmp\/plr-[0-9a-f]{12}$/)]);
    const a = hostDirFor(root, "e2e-abc-123456");
    expect(a.startsWith(root)).toBe(false);
    expect(sockLen(a)).toBeLessThanOrEqual(103);
    expect(hostDirFor(root, "e2e-abc-123456")).toBe(a);
    expect(hostDirFor(root, "e2e-abc-123457")).not.toBe(a);
    expect(hostDirFor(root + "2", "e2e-abc-123456")).not.toBe(a);
  });

  it("refuses when no base directory is short enough (fail closed)", () => {
    const root = "/x/" + "d".repeat(150);
    expect(() => hostDirFor(root, "id", ["/" + "t".repeat(120)])).toThrow(/no short directory/);
    expect(() => hostDirFor(root, "id", ["relative"])).toThrow(/no short directory/);
  });

  it("a Unix socket can really be bound under the fallback dir for a 200-byte root", async (ctx) => {
    const root = "/" + "p".repeat(200) + "/.run";
    const dir = hostDirFor(root, `t-${process.pid}-${Date.now().toString(36)}`, [tmpdir()]);
    try {
      mkdirSync(dir, { mode: 0o700 });
      const priv = join(dir, "tdx-abc123");
      mkdirSync(priv, { mode: 0o700 });
      const sock = join(priv, "q.sock");
      expect(Buffer.byteLength(sock)).toBeLessThanOrEqual(103);
      const server = createServer();
      const bound = await new Promise<NodeJS.ErrnoException | null>((res) => { server.once("error", res); server.listen(sock, () => res(null)); });
      // Only a sandbox that forbids binding any Unix socket (listen EPERM) skips; every other failure fails the test.
      if (bound?.code === "EPERM") return ctx.skip("this environment forbids binding Unix sockets");
      if (bound) throw bound;
      expect(statSync(sock).isSocket()).toBe(true);
      await new Promise<void>((res) => server.close(() => res()));
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });
});
