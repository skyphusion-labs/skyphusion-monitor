# skyphusion-monitor

External **security-posture + uptime** monitor: a standalone Cloudflare Worker (cron, every 5 min)
that probes the public skyphusion surfaces from CFs global edge -- a true *outside-the-fleet*
vantage and a **separate failure domain** from the Hetzner fleet and from Gatus-on-dischord (which
sees the inside view). Chosen over a US Hetzner box (the retired nofx idea): $0, no box to manage,
no cross-zone networking, better/global vantage.

## What it checks
- **uptime** -- the public surfaces serve (2xx/3xx): apex + www, the blog (skyphusion.net),
  play (AI Playground), status (Gatus), auth (Authentik), ntfy.
- **security posture** (a change = regression, alerted as SECURITY):
  - `vivijure.skyphusion.org/api/*` must answer **401/403** to an anonymous edge fetch -- a `200`
    means the CF Access gate dropped (data-plane exposure).
  - `vivijure-studio.skyphusion.workers.dev/api/*` must answer **404** -- the F1 tripwire: if
    `workers_dev` is ever re-enabled, the unauthenticated backdoor reopens and this fires.

## Alerting
Publishes to **ntfy** (`MONITOR_TOPIC`) ONLY when a check fails its expectation (quiet when healthy).
Posture regressions go out at `urgent` priority. Auth via the `NTFY_TOKEN` secret (a least-privilege
ntfy publish token scoped to the alerts topic).

## Config / deploy
- Bindings are mirrored in `src/env.ts` (hand-authored Env).
- `wrangler secret put NTFY_TOKEN` then `npm run deploy`. `account_id` comes from `CLOUDFLARE_ACCOUNT_ID`.
- Cron `*/5 * * * *`. No public route (cron-only); `/health` + gated `/run?key=` exist if a route is added.

## Follow-ups (v2)
- TLS cert-expiry checks (Workers `fetch` does not expose the peer cert; needs a TLS-probe API).
- Dead-mans-switch: ping healthchecks.io each successful run so a DEAD monitor itself alerts
  (HEALTHCHECKS_IO_TOKEN is already in crew-secrets).
- Widen posture checks as more Access-gated surfaces land.
