# skyphusion-monitor

External **security-posture + uptime** monitor: a standalone Cloudflare Worker (cron, every 5 min)
that probes the public skyphusion surfaces from CFs global edge -- a true *outside-the-fleet*
vantage and a **separate failure domain** from the Hetzner fleet and from internal Gatus (which
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
  - `chat-plus.skyphusion.org` (openwebui-friends, trusted-email-header SSO) must answer the
    Access login **302** (or 401/403) to an anonymous fetch -- a `200`/OpenWebUI markup means
    the Access gate dropped and the friends instance is serving anon on Unified Billing.
  - `play.skyphusion.org` (prism, an AI-spend surface), `chat.skyphusion.org` (free-tier
    OpenWebUI), and `status.skyphusion.org` (Gatus, internal topology) must likewise answer
    the Access login **302** (or 401/403) anonymously -- a `200`/app markup on any of them
    means that Access gate dropped (monitor#17). Soak hosts are deliberately excluded until they
    graduate from pre-production monitoring.

## Alerting
Publishes to **ntfy** (`MONITOR_TOPIC`) ONLY when a check fails its expectation (quiet when healthy).
Posture regressions go out at `urgent` priority. Auth via the `NTFY_TOKEN` secret (a least-privilege
ntfy publish token scoped to the alerts topic).

## Config / deploy
- Bindings are mirrored in `src/env.ts` (hand-authored Env).
- `wrangler secret put NTFY_TOKEN` then `npm run deploy`. `account_id` comes from `CLOUDFLARE_ACCOUNT_ID`.
- Cron `*/5 * * * *`. No public route (cron-only); `/health` + gated `/run?key=` exist if a route is added.

## TLS cert-expiry probe (monitor#3 part 2)
Workers `fetch` cannot read the peer cert, so expiry comes from the CF API instead: a daily
(KV-gated, ~20h interval) sweep lists the account's active zones and each zone's
`ssl/certificate_packs`, and ntfy-warns (`high`, not `urgent`) when any ACTIVE cert is within
14 days of `expires_on`. Info-only on `/health` (`cert: {soonestDays, warned, probeError,
ageSec}`; never flips status -- Universal SSL auto-renews ~30d out, and a fully-expired cert
already fails the uptime probes). Auth via `CF_CERT_READ_TOKEN`, a READ-scoped per-function
CF token (Zone Read + SSL and Certificates Read only); unset -> the probe no-ops. A probe
error is recorded to KV (visible on `/health`) and retried at the next daily window, never
paged: the surfaces themselves stay covered by the uptime checks.

## Follow-ups (v2)
- ~~TLS cert-expiry checks~~ DONE (monitor#3 part 2, above).
- ~~Dead-mans-switch~~ DONE twice over: scheduled-run HC.io ping (monitor#3 part 1) + the
  mail-delivery dead-man (#278).
- Widen posture checks as more Access-gated surfaces land.
