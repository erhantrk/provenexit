// GET /api/status: the result of getStatus() from the repo's status bundle, cached for 30 s.
import { getStatus } from "./_lib/provenexit-status.mjs";

export default async function handler(req, res) {
  res.setHeader("content-type", "application/json; charset=utf-8");
  if (req.method !== "GET" && req.method !== "HEAD") {
    res.statusCode = 405;
    res.setHeader("allow", "GET, HEAD");
    res.setHeader("cache-control", "no-store");
    return res.end(JSON.stringify({ error: "method not allowed" }));
  }
  try {
    const status = await getStatus(); // defaults = the live testnet deployment
    res.statusCode = 200;
    res.setHeader(
      "cache-control",
      status.error === null ? "public, max-age=0, s-maxage=30, stale-while-revalidate=30" : "public, max-age=0, s-maxage=10",
    );
    res.end(JSON.stringify(status));
  } catch (e) {
    res.statusCode = 200;
    res.setHeader("cache-control", "no-store");
    const reason = e instanceof Error ? e.message : String(e);
    res.end(JSON.stringify({ checked_at: new Date().toISOString(), error: `status function failed: ${reason.slice(0, 200)}` }));
  }
}
