# skyphusion-monitor

External **security-posture + uptime** monitor: a standalone Cloudflare Worker (cron, every 5 min)
that probes the public skyphusion surfaces from Cloudflare's global edge. $0, no box to manage,
no cross-zone networking, global vantage.

> **Post-fleet (2026-09-25).** The Hetzner fleet was cut on 2026-09-24, and with it the internal
> Gatus board this Worker used to complement. That makes the separate-failure-domain argument
> STRONGER, not weaker: this is now the ONLY uptime and posture vantage on the estate, and its
> alert path deliberately runs entirely on services we do not host (Cloudflare cron -> Telegram,
> plus Healthchecks.io watching for the absence of a cron ping). Nothing in the alarm chain
> depends on infrastructure that could fail in the same event it is meant to report.

## What it checks

**The probe inventory is `config/monitors.json`** (monitor#42) -- **29 checks** (21 uptime,
8 posture), re-derived from live measurement on 2026-09-25 rather than from recollection: every
hostname was resolved against two independent resolvers and probed anonymously before being
listed or dropped. Two kinds:

- **uptime** -- the public surfaces serve what an outsider should get: the skyphusion and
  vivijure sites, demos and panel shells, the MUD worlds (hollow, dustfall), the grid-hub
  federation door, common-thread, the postern demo zone (apex and www redirect to demo),
  the court-record site (rockenhaus.net), GitHub Pages, and the search-MCP alive tripwire.
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
    (the postern custom domain, the search-internal MCP door, the hosted studio MCP
    door at studio-mcp.vivijure.com, the studio control-plane API, crew-bus).
    `studio-mcp-propagandhi.skyphusion.org` is retired (local studio no longer public).
    These are all CUSTOM-domain hostnames, which this vantage
    CAN read honestly. Self-auth on a `*.workers.dev` hostname (slate-search, slate-logs,
    sidvicious-search) is NOT probeable from here and belongs to the fleet Gatus vantage
    (monitor#44); their workers.dev *state* is asserted by `COVER.workers-dev`.
  - **Dead hostnames are removed, not left to rot.** A check against a hostname that no
    longer resolves is not a dormant check; it is a permanent guaranteed failure, and a board
    that is always red is how a real outage gets lost. The 2026-09-25 rebuild dropped nine
    such checks (auth, ntfy, analytics, chat, chat-plus, search, grafana, all NXDOMAIN on two
    resolvers, plus the status board whose DNS record still resolves to a CF 530).

### Adding or changing a check (one place)

Edit `config/monitors.json` -- schema is `CheckConfig` in `src/validate.ts` (`name`, `url`
https-only, `ok[]`, `kind: uptime|posture`, optional `bodyMustNotInclude[]`,
`requireHeaders{}`, `note`, `timeoutMs`). CI validates the file (`tests/config.test.ts`:
parseable, unique names, posture-allowing-2xx must carry a content assertion) and the
tagged deploy ships it (`v*`; a bare merge to main never redeploys). `src/index.ts` is the engine only -- zero estate hostnames in
source. At runtime an invalid inventory **fails closed**: `/health` flips RED, one `urgent`
alert fires (KV-deduped 6h), and no empty check set ever runs silently.

Operational knobs are wrangler `[vars]` with safe in-code defaults (`src/config.ts`):
`FETCH_TIMEOUT_MS`, `RETRY_DELAY_MS`, `HEALTH_STALE_MIN`, `CERT_WARN_DAYS`,
`CERT_CHECK_INTERVAL_HOURS`, `WORKERSDEV_SWEEP_INTERVAL_MIN`, `DEADMAN_FROM`, `PROBE_USER_AGENT`.

## Alerting
Sends to **Telegram**, via the bot Conrad already runs (`skyphusion-gatus`), ONLY when a check
fails its expectation (quiet when healthy). Posture regressions are prefixed `[URGENT]`.

**Telegram by ruling, not by default (fc#2172, 2026-09-26):** *"Telegram as the primary with
postern email as the secondary."* The previous target was public **ntfy.sh**, which was
DECLINED: alert bodies name hostnames, service names and failure modes, i.e. estate topology,
which is exactly the category the pre-public scans exist to keep out of third-party hands, and
ntfy.sh was a NEW vendor for a problem two already-trusted ones solve. Telegram is already
trusted in this estate, so this widens nothing.

The path is still cloud -> cloud -> phone, which is the part that was always right: an alert
channel running on our own infrastructure is not a channel, it is a second thing to lose in the
same outage.

**REUSE the one bot.** `GATUS_TELEGRAM_BOT_TOKEN` and `GATUS_TELEGRAM_CHAT_ID` are the names the
fleet-era Gatus runbook already used, on purpose. A second bot pointed at the same human is two
things to keep alive, and one of them rots silently.

**Secondary (postern email) is NOT wired yet, and that is deliberate.** It is blocked on
fc#2093: postern outbound send is broken today (`E_DELIVERY_FAILED` / relay upstream 530, the
relay was a fleet host). A secondary declared before it can deliver is mute from birth, which is
the arriving-but-unwatched failure in a new costume.

### Mute is a FAILURE, not a quiet day (fc#2079)
This Worker was found **red and silent**: three checks failing, self-marked sick, and every page
going to a host answering 530. That is the worst state a monitor can be in, because every other
defect surfaces as an alert and a defect in alerting surfaces as nothing. Three mechanisms now
make it impossible to be in that state unobserved:

- **`notify()` returns a verdict.** It used to await `fetch` and discard the `Response`, so a 401
  from a rotated token or a 403 from a blocked bot looked exactly like a delivered page. It now
  returns `false` on any non-2xx, on a throw, and on an unconfigured transport.
- **`/health` reports `alerting: "ok" | "mute"`, and a mute flips it RED with zero check
  failures.** An unset channel is a broken monitor on a quiet day; waiting for an outage to find
  out is how this happened.
- **A mute channel SUPPRESSES the cron dead-man ping**, so Healthchecks.io (an independent
  failure domain that does not share our fate) pages about the monitor itself. A self-check
  cannot detect the class where the instrument that would report the failure is the one that
  failed, so a second observer does it.

`tests/notify.test.ts` holds all three, and each was watched going RED against the previous
behaviour before being trusted (revert the response check and the mute-sick term: 4 tests fail).

## Config / deploy
- Bindings are mirrored in `src/env.ts` (hand-authored Env).
- `account_id` comes from `CLOUDFLARE_ACCOUNT_ID` at deploy time; it never reaches the runtime.
- **Runtime secrets, each per-function, set once via `wrangler secret put`. Deleting a Worker
  script deletes all of them, so a restore that sets only the obvious one comes up mute.**
  Set them BEFORE the first tagged deploy; the ordering is not cosmetic, because a Worker whose
  cron is live but whose alert channel is unset is worse than no Worker at all (it looks healthy
  and cannot page).

  | secret | required | unset behaviour |
  |---|---|---|
  | `GATUS_TELEGRAM_BOT_TOKEN` | **yes** | alerting MUTE: `/health` RED, cron dead-man ping SUPPRESSED so HC.io pages |
  | `GATUS_TELEGRAM_CHAT_ID` | **yes** | same as above; both are required and neither is optional |
  | `HC_CRON_PING_URL` | **yes** | no monitor-liveness dead-man at all |
  | `CF_WORKERS_READ_TOKEN` + `CF_ACCOUNT_ID` | **yes** | `COVER.workers-dev` fails CLOSED and pages hourly; deliberate, since an absent credential must not read as "nothing exposed" |
  | `CF_CERT_READ_TOKEN` | no | cert-expiry probe no-ops |
  | `HC_DEADMAN_PING_URL` | **no, currently DORMANT** | `email()` no-ops. Its sender was a fleet cron (`mail-relay-deadman.sh`) that no longer exists, so setting it would create a check that can only page. Leave unset until a replacement sender exists. |
- Cron `*/5 * * * *`. Cron primary; also public host `monitor.skyphusion.org`; `/health` + gated `/run?key=` exist if a route is added.

## TLS cert-expiry probe (monitor#3 part 2)
Workers `fetch` cannot read the peer cert, so expiry comes from the CF API instead: a daily
(KV-gated, ~20h interval) sweep lists the account's active zones and each zone's
`ssl/certificate_packs`, and warns (non-urgent) when any ACTIVE cert is within
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
- ~~Dead-mans-switch~~ scheduled-run HC.io ping (monitor#3 part 1) is the live one. The
  mail-delivery dead-man (#278) is **DORMANT**: its sender was a fleet cron that died on
  2026-09-24, so the code path stays (it no-ops on an unset secret) but the HC check must not
  be wired until something sends again. Retiring it properly, or re-pointing it at a
  Cloudflare-side sender, is an open decision.
- ~~Widen posture checks as more Access-gated surfaces land~~ DONE (monitor#42: full live
  inventory + config-driven checks; new surfaces are a `config/monitors.json` edit).
- Optional: alert title/priority/tag policy as config (still inline in the engine).
- Self-auth coverage for the allowed `*.workers.dev` hostnames. Unprobeable from this Worker by
  construction (CF 1042), and the fleet Gatus vantage that used to carry it (monitor#44) is
  gone, so this is currently UNCOVERED rather than covered elsewhere. Do not read monitor#44 as
  a live compensating control anywhere in this repo.
- Re-reconcile the `workersDev` allowance list against the account. It was last checked on
  2026-08-15 and cannot be verified without `CF_WORKERS_READ_TOKEN`.

## Who this is for

Anyone running a small estate of public surfaces who wants an **independent** vantage on uptime
and on auth-gate regressions: one cron Worker, a config file of expectations, and an alert path
that does not share a failure domain with the thing it watches.

## Links

- **Skyphusion Labs:** https://skyphusion.org · **Org:** https://github.com/skyphusion-labs

## License

[AGPL-3.0-only](LICENSE) (C) 2026 Conrad Rockenhaus. Run a modified version as a network service and the AGPL has you offer users the corresponding source. See [NOTICE](NOTICE).
