# Changelog

## v0.7.0

**feat(restore): post-fleet rebuild -- inventory re-derived from measurement, alerting repointed to ntfy.sh.**

The Worker script was deleted in error on 2026-09-25 during the fleet teardown, having been
read as unwired because it had no route attached. It has no route BY DESIGN; it is
cron-triggered. Deleting a script also deletes its secrets, so this is a rebuild rather than a
redeploy, and the estate it was built for no longer exists.

**Alerting repointed to ntfy.sh, and the mute bug that repoint exposed.** `NTFY_URL` was the
self-hosted `ntfy.skyphusion.org`, which is gone. The off-box path must be cloud to cloud to
phone so it survives the loss of everything we host. Two changes that had to come with it:

- `notifyTarget()` (new, exported) replaces an inline guard that required `NTFY_TOKEN` before
  publishing anything. ntfy.sh takes an anonymous POST and there is no token, so on the new
  target that guard would have returned early on EVERY alert and left the monitor permanently
  and silently mute, with the cron firing, `/health` green and the dead-man satisfied. A
  monitor that cannot page is indistinguishable from an estate with nothing wrong.
  `tests/notify.test.ts` covers it and was watched failing against the old guard before the fix
  was accepted.
- `MONITOR_TOPIC` moved from `[vars]` to a SECRET. This repo is public and an unauthenticated
  ntfy.sh topic is protected only by its name, so a topic in a tracked file lets anyone page the
  phone or forge an all-clear.

**Inventory: 33 checks -> 29** (20 uptime + 13 posture -> 21 uptime + 8 posture). Every hostname
was resolved against two independent resolvers and probed anonymously on 2026-09-25 before being
kept, dropped or added; nothing here rests on recollection.

- REMOVED, 9 checks, dead surfaces: `authentik`, `ntfy`, `analytics-tracker`,
  `F2.analytics-access`, `F2.chat-access`, `F2.chatplus-access`, `F2.search-access`,
  `F2.grafana-access` (all NXDOMAIN on both resolvers), and `status-gatus` (DNS record still
  resolves, origin gone, CF 530). Same class as the v0.6.3 and v0.6.0 removals: a retired
  hostname is alert noise, not a posture finding.
- ADDED, 5 checks, each measured first: `common-thread` (200, real app; the fc#1194 removal was
  made while it was NXDOMAIN and no longer applies), `postern-demo`, `postern-apex` and
  `postern-www` (the public posternonline.com demo zone, apex and www 301 to demo), and
  `vivijure-panel` (panel shell root, 200, the same public-shell-with-self-authing-API shape as
  `studio-shell`).
- All 29 were driven through the real engine locally: 29 of 29 pass against the live estate,
  so the rebuilt inventory starts with zero standing failures.

**Known gaps, both credential-blocked and both documented rather than papered over:**
`COVER.workers-dev` fails closed without `CF_WORKERS_READ_TOKEN` + `CF_ACCOUNT_ID`, which is
correct behaviour (an absent credential must not read as "nothing exposed") but does page. The
`workersDev` allowance list cannot be reconciled against the account without that same token,
so it is left unchanged: an entry naming a missing script fails LOUDLY, whereas trimming the
list on a guess would manufacture a pass. The `#278` mail-delivery dead-man is DORMANT because
its sender was a fleet cron; `HC_DEADMAN_PING_URL` must stay unset until something sends again.

Docs: README and CLAUDE.md carry the post-fleet reality, including that `/health` has no
consumer now (Gatus was its only poller) and that any claim of a compensating "fleet Gatus
vantage" (monitor#44) is void.

## v0.6.4

**fix(inventory): record `mt5-risk-agent` on the workers.dev allowance (#87).**

COVER.workers-dev went red after the 2026-09-10 deploy of `mt5-risk-agent`
(`enabled: 4` vs `allowed: 3`). That hostname is the consumed door for
`mt5-risk-bot` (`workers_dev: true`, anon `/ask` 401). The check was right;
the inventory was stale. Do not disable the hostname.

## v0.6.3

**fix(inventory): drop AUTH.studio-mcp.propagandhi.**

The local studio is no longer a public surface. DNS for
`studio-mcp-propagandhi.skyphusion.org` is gone; the CF edge still
answers 530. The posture check expected 401/403, so `/health` stayed
503 and Gatus paged. Same class as the v0.6.0 common-thread NXDOMAIN
removals: a retired hostname is alert noise, not a posture finding.

## v0.6.2

PATCH: dead-man email delivery (fc#1272: normalize From, await HC ping, flush from scheduled(), await KV writes), polyredos on the ping path, plus Cloudflare toolchain / nanoid / undici on main since v0.6.1.


## v0.6.1

**fix(health): `/health` sick includes uptime failures (#58).**

- Root cause: `sick = (last.posture ?? last.failures) > 0`. When `posture` was `0` and
  `failures` was `N` (uptime red, posture clean), nullish coalescing kept `0`, so `sick`
  stayed false and Gatus saw `ok: true` while the same payload reported `failures: N`.
- `sick` is now `(failures ?? 0) > 0 || !!configError`. `posture` remains a separate severity
  count; it no longer gates whether the board goes red.
- Unit test pins the live shape (`posture: 0, failures: 2`) and a CONTROL that the old form
  still evaluates false there.

## v0.6.0

**workers.dev coverage is now DERIVED from the Cloudflare API, not declared (fc#1194, fc#1180 F2).**

- Added `COVER.workers-dev`: enumerates every Worker in the account and asserts each one's
  authoritative `workers.dev` + preview-URL state against an allowance list. A Worker deployed
  tomorrow with `workers.dev` on turns the monitor RED instead of being invisible to it.
- Removed five probes that could not fail. Cloudflare blocks Worker-to-`workers.dev` subrequests
  inside the same account and answers `404 error code: 1042` for every such hostname, ENABLED and
  DISABLED alike (measured 2026-08-01 from a Worker in this account, with a custom-domain control
  returning a real 200 through the same code path). `F1.vivijure-workersdev.cast`,
  `F1.vivijure-workersdev.modules`, `F1.grid-hub-workersdev`, `F1.prism-workersdev` and
  `AUTH.email-inbound.messages` therefore matched their expected 404 forever.
- New fail-closed paths, none of which can degrade to a quiet skip: missing credential, HTTP
  error, success-with-zero-results, truncated enumeration, non-boolean API state, stale verdict.
- Removed the `common-thread-web` and `common-thread-backend` uptime checks: common-thread was
  shelved 2026-07-31 and both hostnames are NXDOMAIN, so both checks were permanent guaranteed
  failures (alert noise that would mask a real outage).
- New per-function secrets `CF_WORKERS_READ_TOKEN` (Workers Scripts:Read only) and
  `CF_ACCOUNT_ID`; new var `WORKERSDEV_SWEEP_INTERVAL_MIN` (default 60).
- `/health` gains a counts-only `coverage` block; script names never leave KV.

## v0.5.1

Release sync bump (2026-07-21). No functional changes in this tag.

