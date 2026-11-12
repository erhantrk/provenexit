// Local development server: the static files, the two API functions, and the headers from vercel.json.
// Usage: node dev-server.mjs [port]   (default 4173, or $PORT)
import { createServer } from "node:http";
import { readFile } from "node:fs/promises";
import { extname, join, normalize, sep } from "node:path";
import { fileURLToPath } from "node:url";

const root = fileURLToPath(new URL(".", import.meta.url));
const port = Number(process.argv[2] ?? process.env.PORT ?? 4173);
const vercel = JSON.parse(await readFile(join(root, "vercel.json"), "utf8"));
const siteHeaders = vercel.headers.find((h) => h.source === "/(.*)").headers;

const TYPES = {
  ".html": "text/html; charset=utf-8", ".css": "text/css; charset=utf-8", ".js": "text/javascript; charset=utf-8",
  ".mjs": "text/javascript; charset=utf-8", ".json": "application/json; charset=utf-8", ".svg": "image/svg+xml",
  ".png": "image/png", ".woff2": "font/woff2", ".txt": "text/plain; charset=utf-8",
};

// Stands in for the CDN: one stored /api/status answer, kept for its s-maxage.
let cached = null;
async function status(req, res) {
  if (cached !== null && Date.now() < cached.until) {
    res.writeHead(200, cached.headers);
    return res.end(cached.body);
  }
  const { default: handler } = await import("./api/status.mjs");
  const chunks = [];
  const end = res.end.bind(res);
  res.end = (body) => {
    if (body !== undefined) chunks.push(Buffer.from(body));
    const maxAge = /s-maxage=(\d+)/.exec(String(res.getHeader("cache-control") ?? ""));
    if (res.statusCode === 200 && maxAge !== null) {
      cached = { until: Date.now() + Number(maxAge[1]) * 1000, headers: res.getHeaders(), body: Buffer.concat(chunks) };
    }
    return end(body);
  };
  return handler(req, res);
}

createServer(async (req, res) => {
  try {
    for (const h of siteHeaders) res.setHeader(h.key, h.value);
    const url = new URL(req.url, "http://localhost");
    if (url.pathname === "/api/status") return await status(req, res);
    if (url.pathname === "/api/ip") return (await import("./api/ip.mjs")).default(req, res);
    let path = normalize(decodeURIComponent(url.pathname));
    if (path.endsWith(sep)) path += "index.html";
    const file = join(root, path);
    if (!file.startsWith(root) || path.startsWith(`${sep}api${sep}`) || path.includes(`${sep}.`)) throw new Error("not found");
    const body = await readFile(file);
    res.writeHead(200, { "content-type": TYPES[extname(file)] ?? "application/octet-stream", "cache-control": "no-store" });
    res.end(body);
  } catch {
    if (!res.headersSent) res.writeHead(404, { "content-type": "text/plain; charset=utf-8" });
    res.end("Not found");
  }
}).listen(port, "127.0.0.1", () => {
  console.log(`ProvenExit site: http://localhost:${port}/`);
  console.log(`Samples: http://localhost:${port}/?sample=online  (also offline, refused, error)`);
});
