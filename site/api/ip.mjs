// GET /api/ip: the caller's address as this site's server sees it. Not stored, not logged, never cached.
export default function handler(req, res) {
  const forwarded = String(req.headers["x-forwarded-for"] ?? "").split(",")[0].trim();
  const raw = forwarded || String(req.headers["x-real-ip"] ?? "").trim() || req.socket?.remoteAddress || "";
  const ip = raw.replace(/^::ffff:/, "");
  res.statusCode = 200;
  res.setHeader("content-type", "application/json; charset=utf-8");
  res.setHeader("cache-control", "no-store");
  res.end(JSON.stringify({ ip: /^[0-9a-fA-F:.]{2,45}$/.test(ip) ? ip : null }));
}
