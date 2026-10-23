/**
 * Runtime measurement for the mock TDX host: the executables that see plaintext (node for the router and the
 * mock LLM, llama-server for the real LLM) are pinned in the compose (`router.node_sha256`,
 * `llm.runtime_sha256`) and the host refuses to launch anything else.
 *
 * On macOS both executables are small stubs: the code lives in dylibs (`@rpath/libnode.*.dylib`,
 * `libllama-server-impl.dylib`, ggml, …), and ggml `dlopen`s its CPU/Metal backends from `<keg>/libexec`.
 * Hashing only the stub would pin nothing, so a runtime is measured as its **closure**:
 *
 *   - the executable,
 *   - every non-system Mach-O image it links (LC_LOAD_DYLIB / weak / re-export / upward / lazy), transitively,
 *     resolving `@rpath`, `@loader_path` and `@executable_path` the way dyld does,
 *   - every `*.so` / `*.dylib` Mach-O file in `<image dir>/../libexec` of any closure image (dlopen'd plugins,
 *     e.g. ggml backends), and their dependencies.
 *
 * System images (`/usr/lib/…`, `/System/…`) belong to the OS (the mock OS measurement), not the app.
 *
 * `runtime digest = SHA256(manifest)`, manifest = lines `"<sha256 hex> <exe|lib> <leaf name>\n"` sorted by
 * (role, name) — independent of install paths, so the build and the host agree on one machine image.
 *
 * Launching (see `installRuntime`): every closure file is cloned into the host's private 0700 directory and
 * re-hashed THERE; the copy must reproduce the pinned digest, and the copy is what runs (executable from
 * `<dir>/bin`, libraries found via `DYLD_LIBRARY_PATH=<dir>/lib`, which dyld consults by leaf name before any
 * install path, also for `dlopen`). So no swap between measurement and exec can change the code that runs.
 * Residual (documented MOCK limitation): a NEW plugin file added to a libexec directory after measurement would
 * still be found by ggml's directory scan.
 */
import { createHash } from "node:crypto";
import { constants as FS, createReadStream, readdirSync, realpathSync, statSync, type Stats } from "node:fs";
import { chmod, copyFile, mkdir, open } from "node:fs/promises";
import { basename, dirname, join, resolve } from "node:path";
import { HostError } from "./errors.js";

export type RuntimeRole = "exe" | "lib";

export interface RuntimeFile {
  role: RuntimeRole;
  /** Leaf name dyld looks up (`libnode.127.dylib`), or the executable's file name. */
  name: string;
  /** Resolved real path of the measured file. */
  path: string;
  sha256: string;
}

export interface RuntimeClosure {
  exe: RuntimeFile;
  files: RuntimeFile[];
  /** SHA256 of the manifest (64 lowercase hex). */
  digest: string;
}

/** Per-process hash cache for repeated measurements of unchanged files (harnesses only; never used by launch). */
export type RuntimeHashCache = Map<string, string>;

const MAX_FILES = 256;
const MAX_FILE_BYTES = 1024 * 1024 * 1024;
const MAX_HEADER_BYTES = 256 * 1024;
const NAME_RE = /^[A-Za-z0-9][A-Za-z0-9._+@-]{0,127}$/;
const SYSTEM_PREFIXES = ["/usr/lib/", "/System/"];

// Mach-O constants (<mach-o/loader.h>, <mach-o/fat.h>).
const MH_MAGIC_64 = 0xfeedfacf;
const FAT_MAGIC = 0xcafebabe;
const FAT_MAGIC_64 = 0xcafebabf;
const LC_REQ_DYLD = 0x80000000;
const LC_LOAD_DYLIB = 0x0c;
const LC_LOAD_WEAK_DYLIB = (0x18 | LC_REQ_DYLD) >>> 0;
const LC_REEXPORT_DYLIB = (0x1f | LC_REQ_DYLD) >>> 0;
const LC_LAZY_LOAD_DYLIB = 0x20;
const LC_LOAD_UPWARD_DYLIB = (0x23 | LC_REQ_DYLD) >>> 0;
const LC_RPATH = (0x1c | LC_REQ_DYLD) >>> 0; // `>>> 0`: JS bitwise ops are signed
const CPU_TYPE: Readonly<Record<string, number>> = { arm64: 0x0100000c, x64: 0x01000007 };

interface MachoInfo {
  deps: { name: string; weak: boolean }[];
  rpaths: string[];
}

function fail(code = "E_RUNTIME"): never {
  throw new HostError(code);
}

function statFile(path: string): Stats {
  let st: Stats;
  try {
    st = statSync(path);
  } catch {
    return fail();
  }
  if (!st.isFile() || st.size > MAX_FILE_BYTES) fail();
  return st;
}

async function readAt(path: string, offset: number, length: number): Promise<Buffer> {
  const fh = await open(path, "r");
  try {
    const buf = Buffer.alloc(length);
    const { bytesRead } = await fh.read(buf, 0, length, offset);
    return buf.subarray(0, bytesRead);
  } finally {
    await fh.close();
  }
}

/** Parses the load commands of a (thin or fat) Mach-O file; `null` if the file is not Mach-O. */
export async function readMacho(path: string): Promise<MachoInfo | null> {
  const st = statFile(path);
  const head = await readAt(path, 0, Math.min(st.size, 4096));
  if (head.length < 32) return null;
  let base = 0;
  const beMagic = head.readUInt32BE(0);
  if (beMagic === FAT_MAGIC || beMagic === FAT_MAGIC_64) {
    const want = CPU_TYPE[process.arch];
    const n = head.readUInt32BE(4);
    const entry = beMagic === FAT_MAGIC ? 20 : 32;
    if (want === undefined || n < 1 || n > 32 || 8 + n * entry > head.length) fail("E_RUNTIME_FORMAT");
    let found = -1;
    for (let i = 0; i < n; i++) {
      const o = 8 + i * entry;
      if (head.readInt32BE(o) === want) found = beMagic === FAT_MAGIC ? head.readUInt32BE(o + 8) : Number(head.readBigUInt64BE(o + 8));
    }
    if (found < 0) fail("E_RUNTIME_FORMAT");
    base = found;
  } else if (head.readUInt32LE(0) !== MH_MAGIC_64) {
    return null;
  }
  const hdr = await readAt(path, base, 32);
  if (hdr.length < 32 || hdr.readUInt32LE(0) !== MH_MAGIC_64) fail("E_RUNTIME_FORMAT");
  const ncmds = hdr.readUInt32LE(16);
  const sizeofcmds = hdr.readUInt32LE(20);
  if (sizeofcmds > MAX_HEADER_BYTES || ncmds > 4096) fail("E_RUNTIME_FORMAT");
  const cmds = await readAt(path, base + 32, sizeofcmds);
  if (cmds.length !== sizeofcmds) fail("E_RUNTIME_FORMAT");
  const info: MachoInfo = { deps: [], rpaths: [] };
  const lcStr = (cmdOff: number, cmdSize: number): string => {
    const strOff = cmds.readUInt32LE(cmdOff + 8);
    if (strOff < 12 || strOff >= cmdSize) fail("E_RUNTIME_FORMAT");
    const raw = cmds.subarray(cmdOff + strOff, cmdOff + cmdSize);
    const nul = raw.indexOf(0);
    const s = (nul < 0 ? raw : raw.subarray(0, nul)).toString("utf8");
    if (s.length === 0 || s.length > 1024) fail("E_RUNTIME_FORMAT");
    return s;
  };
  let off = 0;
  for (let i = 0; i < ncmds; i++) {
    if (off + 8 > cmds.length) fail("E_RUNTIME_FORMAT");
    const cmd = cmds.readUInt32LE(off);
    const size = cmds.readUInt32LE(off + 4);
    if (size < 8 || off + size > cmds.length) fail("E_RUNTIME_FORMAT");
    if (cmd === LC_LOAD_DYLIB || cmd === LC_REEXPORT_DYLIB || cmd === LC_LAZY_LOAD_DYLIB || cmd === LC_LOAD_UPWARD_DYLIB) {
      info.deps.push({ name: lcStr(off, size), weak: false });
    } else if (cmd === LC_LOAD_WEAK_DYLIB) {
      info.deps.push({ name: lcStr(off, size), weak: true });
    } else if (cmd === LC_RPATH) {
      info.rpaths.push(lcStr(off, size));
    }
    off += size;
  }
  return info;
}

function isSystem(p: string): boolean {
  return SYSTEM_PREFIXES.some((s) => p.startsWith(s));
}

function exists(p: string): boolean {
  try {
    return statSync(p).isFile();
  } catch {
    return false;
  }
}

function expand(p: string, loaderDir: string, exeDir: string): string {
  if (p.startsWith("@loader_path/") || p === "@loader_path") return resolve(loaderDir, p.slice("@loader_path".length + 1));
  if (p.startsWith("@executable_path/") || p === "@executable_path") return resolve(exeDir, p.slice("@executable_path".length + 1));
  return p;
}

function hashFile(path: string, cache?: RuntimeHashCache): Promise<string> {
  const st = statFile(path);
  const key = `${path}\0${st.dev}\0${st.ino}\0${st.size}\0${st.mtimeMs}\0${st.ctimeMs}`;
  const hit = cache?.get(key);
  if (hit !== undefined) return Promise.resolve(hit);
  return new Promise((ok, ko) => {
    const h = createHash("sha256");
    createReadStream(path)
      .on("data", (c) => h.update(c))
      .on("error", () => ko(new HostError("E_RUNTIME")))
      .on("end", () => {
        const d = h.digest("hex");
        cache?.set(key, d);
        ok(d);
      });
  });
}

/** Canonical manifest digest of a set of runtime files. */
export function runtimeDigest(files: readonly Pick<RuntimeFile, "role" | "name" | "sha256">[]): string {
  const lines = files
    .map((f) => `${f.sha256} ${f.role} ${f.name}\n`)
    .sort((a, b) => {
      const ka = a.slice(65);
      const kb = b.slice(65);
      return ka < kb ? -1 : ka > kb ? 1 : 0;
    });
  return createHash("sha256").update(lines.join("")).digest("hex");
}

/**
 * Measures the runtime closure of executable `exePath` (see module doc).
 * @throws HostError E_RUNTIME (missing/unreadable file, too many files, name clash), E_RUNTIME_FORMAT
 */
export async function measureRuntime(exePath: string, o: { cache?: RuntimeHashCache } = {}): Promise<RuntimeClosure> {
  let exeReal: string;
  try {
    exeReal = realpathSync(exePath);
  } catch {
    return fail();
  }
  statFile(exeReal);
  const exeDir = dirname(exeReal);
  const exeName = basename(exeReal);
  if (!NAME_RE.test(exeName)) fail();
  const exeInfo = await readMacho(exeReal);
  if (exeInfo === null) fail("E_RUNTIME_FORMAT");

  /** leaf name → real path (one file per leaf name: DYLD_LIBRARY_PATH resolves by leaf). */
  const libs = new Map<string, string>();
  const visited = new Set<string>([exeReal]);
  const pluginDirs = new Set<string>();
  type Item = { real: string; info: MachoInfo; rpathChain: { rpath: string; loaderDir: string }[] };
  const queue: Item[] = [];
  const enqueue = (real: string, info: MachoInfo, parentChain: Item["rpathChain"]) => {
    const dir = dirname(real);
    queue.push({ real, info, rpathChain: [...info.rpaths.map((rpath) => ({ rpath, loaderDir: dir })), ...parentChain] });
    pluginDirs.add(resolve(dir, "..", "libexec"));
  };
  const addLib = async (leaf: string, real: string, chain: Item["rpathChain"]) => {
    if (!NAME_RE.test(leaf)) fail();
    const prev = libs.get(leaf);
    if (prev !== undefined && prev !== real) fail(); // two different files under one leaf name
    libs.set(leaf, real);
    if (libs.size + 1 > MAX_FILES) fail();
    if (visited.has(real)) return;
    visited.add(real);
    const info = await readMacho(real);
    if (info === null) fail("E_RUNTIME_FORMAT");
    enqueue(real, info, chain);
  };
  enqueue(exeReal, exeInfo, []);

  const drain = async () => {
    while (queue.length > 0) {
      const item = queue.shift() as Item;
      const loaderDir = dirname(item.real);
      for (const dep of item.info.deps) {
        if (isSystem(dep.name)) continue;
        let candidates: string[];
        if (dep.name.startsWith("@rpath/")) {
          const rest = dep.name.slice("@rpath/".length);
          candidates = item.rpathChain.map((r) => join(expand(r.rpath, r.loaderDir, exeDir), rest));
        } else {
          candidates = [expand(dep.name, loaderDir, exeDir)];
        }
        const hit = candidates.find((c) => c.startsWith("/") && exists(c));
        if (hit === undefined) {
          if (dep.weak) continue;
          fail();
        }
        let real: string;
        try {
          real = realpathSync(hit);
        } catch {
          return fail();
        }
        if (isSystem(real)) continue;
        await addLib(basename(dep.name), real, item.rpathChain);
      }
    }
  };
  await drain();
  // dlopen'd plugins (ggml backends): Mach-O *.so / *.dylib files in <image dir>/../libexec.
  const scanned = new Set<string>();
  for (;;) {
    const dirs = [...pluginDirs].filter((d) => !scanned.has(d));
    if (dirs.length === 0) break;
    for (const d of dirs) {
      scanned.add(d);
      let names: string[];
      try {
        names = readdirSync(d).sort();
      } catch {
        continue;
      }
      for (const n of names) {
        if (!/\.(?:so|dylib)$/.test(n)) continue;
        const p = join(d, n);
        if (!exists(p)) continue;
        if ((await readMacho(p)) === null) continue;
        await addLib(n, realpathSync(p), []);
      }
    }
    await drain();
  }

  const files: RuntimeFile[] = [{ role: "exe", name: exeName, path: exeReal, sha256: await hashFile(exeReal, o.cache) }];
  for (const [name, path] of [...libs.entries()].sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0))) {
    files.push({ role: "lib", name, path, sha256: await hashFile(path, o.cache) });
  }
  return { exe: files[0] as RuntimeFile, files, digest: runtimeDigest(files) };
}

/**
 * Clones a measured closure into `dir` (`bin/<exe>` 0500, `lib/<leaf>` 0400), re-hashes the COPIES and checks
 * they reproduce `expectedDigest`. Returns what to execute and the `DYLD_LIBRARY_PATH` to run it with.
 * @throws HostError E_MEASUREMENT_MISMATCH if the copies differ from the pinned digest
 */
export async function installRuntime(c: RuntimeClosure, dir: string, expectedDigest: string): Promise<{ exe: string; libDir: string; env: Record<string, string> }> {
  const bin = join(dir, "bin");
  const lib = join(dir, "lib");
  await mkdir(bin, { recursive: false, mode: 0o700 }).catch(() => fail());
  await mkdir(lib, { recursive: false, mode: 0o700 }).catch(() => fail());
  const copied: RuntimeFile[] = [];
  for (const f of c.files) {
    if (!NAME_RE.test(f.name)) fail();
    const dst = join(f.role === "exe" ? bin : lib, f.name);
    // APFS clone when possible (copy-on-write: later writes to the source never reach the copy).
    await copyFile(f.path, dst, FS.COPYFILE_EXCL | FS.COPYFILE_FICLONE).catch(() => fail());
    await chmod(dst, f.role === "exe" ? 0o500 : 0o400);
    copied.push({ ...f, path: dst, sha256: await hashFile(dst) });
  }
  const digest = runtimeDigest(copied);
  if (digest.length !== expectedDigest.length || !timingSafeEqualHex(digest, expectedDigest)) fail("E_MEASUREMENT_MISMATCH");
  return { exe: join(bin, c.exe.name), libDir: lib, env: { DYLD_LIBRARY_PATH: lib } };
}

function timingSafeEqualHex(a: string, b: string): boolean {
  let d = a.length ^ b.length;
  for (let i = 0; i < Math.min(a.length, b.length); i++) d |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return d === 0;
}
