# skyphusion-monitor

External **security-posture + uptime** monitor: a standalone Cloudflare Worker (cron, every 5 min)
that probes the public skyphusion surfaces from CFs global edge -- a true *outside-the-fleet*
vantage and a **separate failure domain** from the Hetzner fleet and from internal Gatus (which
sees the inside view). Chosen over a US Hetzner box (the retired nofx idea): $0, no box to manage,
no cross-zone networking, better/global vantage.

## What it checks

**The probe inventory is `config/monitors.json`** (monitor#42) -- ~40 checks across every
presently-online public surface (grounded in the live CF API inventory: worker custom domains,
Access apps, DNS; 2026-07-18). Two kinds:

- **uptime** -- the public surfaces serve what an outsider should get: the skyphusion +
  vivijure sites and demos, the MUD worlds, common-thread, the status board, auth, ntfy,
  the court-record site (rockenhaus.net), GitHub Pages, the Umami tracker path.
- **security posture** (a change = regression, alerted as SECURITY):
  - **F1 tripwires:** `workers_dev` must stay OFF where the custom domain is the only door
    (vivijure-studio, grid-hub, prism/skyphusion-llm) -- a serve = the unauthenticated
    backdoor reopened.
  - **F2 Access gates:** anonymous fetches must hit the Access login **302** (or 401/403) on
    vivijure, chat-plus, play, chat, search (SearXNG), analytics (Umami dashboard), grafana --
    a `200`/app markup means the gate dropped.
  - **AUTH self-auth tripwires:** in-worker auth must keep answering **401/403** anonymously
    (email-inbound + postern domain, slate-search + sidvicious-search, the search-internal and
    studio MCP doors, the studio control-plane API, crew-bus).
  - `status.skyphusion.org` (Gatus) is **intentionally public** (uptime-only); write API
    stays `GATUS_PUSH_TOKEN` bearer-gated.

### Adding or changing a check (one place)

Edit `config/monitors.json` -- schema is `CheckConfig` in `src/validate.ts` (`name`, `url`
https-only, `ok[]`, `kind: uptime|posture`, optional `bodyMustNotInclude[]`,
`requireHeaders{}`, `note`, `timeoutMs`). CI validates the file (`tests/config.test.ts`:
parseable, unique names, posture-allowing-2xx must carry a content assertion) and the
push-to-main deploy ships it. `src/index.ts` is the engine only -- zero estate hostnames in
source. At runtime an invalid inventory **fails closed**: `/health` flips RED, one `urgent`
ntfy fires (KV-deduped 6h), and no empty check set ever runs silently.

Operational knobs are wrangler `[vars]` with safe in-code defaults (`src/config.ts`):
`FETCH_TIMEOUT_MS`, `RETRY_DELAY_MS`, `HEALTH_STALE_MIN`, `CERT_WARN_DAYS`,
`CERT_CHECK_INTERVAL_HOURS`, `DEADMAN_FROM`, `PROBE_USER_AGENT`.

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
- ~~Widen posture checks as more Access-gated surfaces land~~ DONE (monitor#42: full live
  inventory + config-driven checks; new surfaces are a `config/monitors.json` edit).
- Optional: ntfy title/priority/tag policy as config (still inline in the engine).

## Who this is for

Fleet operators who want an **outside-the-fleet** vantage on public Skyphusion surfaces (uptime + Access-gate regressions), separate from internal Gatus.

## Links

- **Skyphusion Labs:** https://skyphusion.org · **Org:** https://github.com/skyphusion-labs

## License

[AGPL-3.0-only](LICENSE) (C) 2026 Conrad Rockenhaus. Run a modified version as a network service and the AGPL has you offer users the corresponding source. See [NOTICE](NOTICE).
