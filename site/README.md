# ProvenExit demo site

One static page plus two small functions. No framework, no build step, no runtime dependency, no third-party request.

## Run it locally

```sh
cd site
npm run dev        # http://localhost:4173/  (live data from getStatus())
npm test           # state logic and the colour rule
```

Sample states, on localhost only:

- http://localhost:4173/?sample=online (verified)
- http://localhost:4173/?sample=offline
- http://localhost:4173/?sample=refused
- http://localhost:4173/?sample=error
- also `stale` and `offline-retired` (the real sample from the retired registry)

`npm run fixtures` rebuilds `fixtures/` from `../status/sample-*.json` and the status bundle.

## Layout

| Path | What it is |
|---|---|
| `index.html` | all sections and static copy; unlit until a response arrives |
| `assets/state.js` | `deriveState()`, stage grouping, allowlist status, formatters; pure |
| `assets/app.js` | fetch, 15 s poll, render, copy buttons, the lighting sequence |
| `assets/styles.css` | tokens and layout; one violet brand accent (`--accent`, #5034E6) for labels, links, lines, icons and grounds; green and red only in the last block, under the page state |
| `assets/motion.js`, `assets/motion-flag.js` | reveals, count-ups, the hero flow, the route steps, the history line; transform and opacity only; off under `prefers-reduced-motion` |
| `assets/config.js` | `demoVideoUrl`; the video link shows only when it is set |
| `api/status.mjs` | `getStatus()` from `api/_lib/provenexit-status.mjs`, cached 30 s; answers within 55 s (`api/_lib/deadline.mjs`) |
| `api/ip.mjs` | the caller's address from the request headers, never cached |
| `fixtures/`, `test/`, `dev-server.mjs` | local only (`.vercelignore`) |

`api/_lib/provenexit-status.mjs` is a byte-for-byte copy of `../status/provenexit-status.mjs`; a test fails if they
differ. After rebuilding the bundle, copy it again.

## Hosting

Vercel, with `site/` as the project root, Node 22. `vercel.json` sets the headers (CSP `default-src 'self'`) and
60 s for `api/status`. Nothing is deployed from this folder by any script.
