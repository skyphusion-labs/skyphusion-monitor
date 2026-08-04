# Changelog

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

