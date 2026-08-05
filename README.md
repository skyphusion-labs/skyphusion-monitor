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
  - **`COVER.workers-dev` (derived coverage, fc#1194):** the ONE check here that is not a
    probe, because it cannot be one. Cloudflare blocks Worker-to-`workers.dev` subrequests
    inside the same account and answers `404 error code: 1042` for every such hostname,
    enabled and disabled alike, so the five workers.dev probes this replaces matched their
    expected 404 forever. Instead the check enumerates **every Worker in the account from the
    Cloudflare API** and asserts each one's authoritative `workers.dev` and preview-URL state
    against the allowance list in `config/monitors.json`. A Worker deployed tomorrow with
    `workers.dev` on turns the monitor RED without anyone remembering to add it. See
    "workers.dev coverage" below.
  - **F2 Access gates:** anonymous fetches must hit the Access login **302** (or 401/403) on
    vivijure, chat-plus, chat, search (SearXNG), analytics (Umami dashboard), grafana -- a
    `200`/app markup means the gate dropped. **Exception -- play is public:**
    `F2.play-public` expects **200** (`AUTH_MODE=public`, first-party auth; Access retired on
    play).
  - **AUTH self-auth tripwires:** in-worker auth must keep answering **401/403** anonymously
    (the postern custom domain, the search-internal and studio MCP doors, the studio
    control-plane API, crew-bus). These are all CUSTOM-domain hostnames, which this vantage
    CAN read honestly. Self-auth on a `*.workers.dev` hostname (slate-search, slate-logs,
    sidvicious-search) is NOT probeable from here and belongs to the fleet Gatus vantage
    (monitor#44); their workers.dev *state* is asserted by `COVER.workers-dev`.
  - `status.skyphusion.org` (Gatus) is **intentionally public** (uptime-only); write API
    stays `GATUS_PUSH_TOKEN` bearer-gated.

### Adding or changing a check (one place)

Edit `config/monitors.json` -- schema is `CheckConfig` in `src/validate.ts` (`name`, `url`
https-only, `ok[]`, `kind: uptime|posture`, optional `bodyMustNotInclude[]`,
`requireHeaders{}`, `note`, `timeoutMs`). CI validates the file (`tests/config.test.ts`:
parseable, unique names, posture-allowing-2xx must carry a content assertion) and the
tagged deploy ships it (`v*`; a bare merge to main never redeploys). `src/index.ts` is the engine only -- zero estate hostnames in
source. At runtime an invalid inventory **fails closed**: `/health` flips RED, one `urgent`
ntfy fires (KV-deduped 6h), and no empty check set ever runs silently.

Operational knobs are wrangler `[vars]` with safe in-code defaults (`src/config.ts`):
`FETCH_TIMEOUT_MS`, `RETRY_DELAY_MS`, `HEALTH_STALE_MIN`, `CERT_WARN_DAYS`,
`CERT_CHECK_INTERVAL_HOURS`, `WORKERSDEV_SWEEP_INTERVAL_MIN`, `DEADMAN_FROM`, `PROBE_USER_AGENT`.

## Alerting
Publishes to **ntfy** (`MONITOR_TOPIC`) ONLY when a check fails its expectation (quiet when healthy).
Posture regressions go out at `urgent` priority. Auth via the `NTFY_TOKEN` secret (a least-privilege
ntfy publish token scoped to the alerts topic).

## Config / deploy
- Bindings are mirrored in `src/env.ts` (hand-authored Env).
- `wrangler secret put NTFY_TOKEN` then `npm run deploy`. `account_id` comes from `CLOUDFLARE_ACCOUNT_ID`.
- Runtime secrets, each per-function and set once via `wrangler secret put`: `NTFY_TOKEN`,
  `HC_DEADMAN_PING_URL`, `HC_CRON_PING_URL`, `CF_CERT_READ_TOKEN`, and (fc#1194)
  `CF_WORKERS_READ_TOKEN` + `CF_ACCOUNT_ID`. **Set the last two BEFORE tagging a release**:
  the coverage check fails CLOSED without them, which is deliberate but will page.
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

## workers.dev coverage (fc#1194 / fc#1180 F2)

Cloudflare Access binds a **hostname**, so an Access policy on a custom domain never covers
`<script>.<subdomain>.workers.dev` for the same Worker, and no zone WAF rule or rate limit
reaches it either. The old tripwires named three Workers that already had it off and none of
the ones that had it on, and reported green throughout a live exposure (fc#1180 F1/F2).

This check makes coverage **derived, not declared**:

1. enumerate every Worker in the account (`/accounts/{id}/workers/scripts`);
2. read each one's authoritative `enabled` / `previews_enabled` (`.../subdomain`);
3. assess against `workersDev.allowed` in `config/monitors.json`.

It FAILS (posture, `/health` RED) on any of: a Worker with `workers.dev` or preview URLs on and
no allowance; an allowance whose Worker no longer has it on (a stale allowance must not rot into
a permanent silent pass); an allowance naming a Worker that does not exist; a zero-length
enumeration (an empty success is indistinguishable from a permission gap -- fc#1180 F5); a
truncated enumeration; a non-boolean state from the API; a missing credential; a verdict that
stopped refreshing. There is deliberately **no path where this degrades to a quiet skip**.

An entry in `workersDev.allowed` RECORDS an exposure, it does not bless it: each allowed Worker
depends on its own code staying correct forever with no platform gate behind it. Every entry
carries a reason and a pointer to what actually covers it.

Auth via `CF_WORKERS_READ_TOKEN` (Account > Workers Scripts > **Read** only) and `CF_ACCOUNT_ID`,
both per-function secrets. The sweep runs at most hourly (`WORKERSDEV_SWEEP_INTERVAL_MIN`,
default 60) and its verdict is projected into every 5-minute run, so `/health` stays RED between
sweeps while a standing failure pages hourly rather than every 5 minutes. `/health` exposes
counts only (`coverage: {ok, scripts, allowed, enabled, probeError, ageSec}`) -- never script
names, same rule as check names and zone names.

**What it still cannot see:** whether an allowed Worker's own auth is actually working. This
vantage cannot probe a `*.workers.dev` hostname at all, so "declared" is not "verified"; that
half lives in the fleet Gatus vantage (monitor#44). It also cannot see Workers outside this
account, Pages projects, or a Worker exposed through a route on a zone it does not enumerate.

## Follow-ups (v2)
- ~~TLS cert-expiry checks~~ DONE (monitor#3 part 2, above).
- ~~Dead-mans-switch~~ DONE twice over: scheduled-run HC.io ping (monitor#3 part 1) + the
  mail-delivery dead-man (#278).
- ~~Widen posture checks as more Access-gated surfaces land~~ DONE (monitor#42: full live
  inventory + config-driven checks; new surfaces are a `config/monitors.json` edit).
- Optional: ntfy title/priority/tag policy as config (still inline in the engine).
- Self-auth coverage for the three allowed `*.workers.dev` hostnames from the fleet Gatus
  vantage (monitor#44) -- unprobeable from this Worker by construction.

## Who this is for

Fleet operators who want an **outside-the-fleet** vantage on public Skyphusion surfaces (uptime + Access-gate regressions), separate from internal Gatus.

## Links

- **Skyphusion Labs:** https://skyphusion.org · **Org:** https://github.com/skyphusion-labs

## License

[AGPL-3.0-only](LICENSE) (C) 2026 Conrad Rockenhaus. Run a modified version as a network service and the AGPL has you offer users the corresponding source. See [NOTICE](NOTICE).
