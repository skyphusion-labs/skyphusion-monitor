# CLAUDE.md

Guidance for Claude Code (and the crew) working in this repo.

## What this is

An external **security-posture + uptime** monitor: a standalone Cloudflare Worker (cron, every
5 minutes) that probes the public skyphusion surfaces from CF's global edge. It runs at
`monitor.skyphusion.org`: $0, no dedicated box, no cross-zone networking. It was designed as a
**separate failure domain** from the self-hosted Hetzner fleet and from internal Gatus (inside
view); both are gone as of 2026-09-24 (fleet decommissioned entirely, self-hosted Gatus with it).
`status.skyphusion.org` still resolved at Cloudflare on 2026-09-25 while the origin behind it
answered CF 530, which is why it is REMOVED from the inventory as dead rather than left in place
as a dormant check.

> **Post-fleet (2026-09-25).** The Hetzner fleet is gone, so internal Gatus
> (`status.skyphusion.org`) is gone with it. This Worker is now the ONLY uptime and posture
> vantage on the estate. Three consequences that bite when editing this repo:
> 1. **Nothing consumes `/health` any more.** Gatus was its only poller, so `/health` is a
>    diagnostic endpoint, not a monitored control. Monitor liveness rests entirely on the
>    `HC_CRON_PING_URL` dead-man, where Healthchecks.io pages on the ABSENCE of a cron ping.
> 2. **Any comment claiming the "fleet Gatus vantage" covers something (monitor#44) is void.**
>    That vantage does not exist. Treat what it used to cover as uncovered, and say so.
> 3. **This Worker is not deployed.** `monitor.skyphusion.org` was NXDOMAIN on 2026-09-25
>    despite `wrangler.toml` defining that route, because the deploy credentials went with the
>    teardown. Read deploy state from a live resolve, never from this doc or from `wrangler.toml`;
>    a defined route is not a live one, and deploying again is a separate, credentialed decision.

> Note: this is NOT Gatus and was never meant to replace it. It is the CF-edge vantage only, so
> being the last vantage standing does NOT mean it covers Gatus's old ground: the inside view is
> simply uncovered now, because there is no fleet to be inside of. Do not assume this Worker fills
> that gap. (The old claim that internal Gatus was "Access-gated" was also wrong independent of the
> teardown: `config/monitors.json` documented `status.skyphusion.org` as intentionally public,
> gating only the push API.)

## Posture notes agents get wrong

- **Most F2 Access-gate checks** expect anonymous `302` / `401` / `403` (gate healthy).
- **`F2.play-public` is the opposite:** `https://play.skyphusion.org/` expects **`200`**. Prism is
  `AUTH_MODE=public` (first-party signup + mandatory per-user BYOK); Access was retired on play.
  Treating play as Access-gated is a defect in the inventory, not a prod outage.
- Probe inventory lives in `config/monitors.json` (config-driven; see README). Do not hardcode a
  surface list in source.
- **Never add a check for a hostname you have not just resolved and probed.** The inventory is
  re-derived from measurement, not from memory or from this file; a check on a dead hostname is a
  permanent failure that masks real outages, and nine of them had to be removed on 2026-09-25.
- **Alerting is TELEGRAM via the existing `skyphusion-gatus` bot, by Conrad ruling fc#2172.**
  Do NOT repoint it at ntfy.sh; he declined that vendor (alert bodies carry estate topology). Do
  NOT mint a second bot; reuse `GATUS_TELEGRAM_BOT_TOKEN` + `GATUS_TELEGRAM_CHAT_ID`. Both are
  REQUIRED, and a missing one means MUTE, which is a `/health` failure AND suppresses the cron
  dead-man so HC.io pages. Never log the transport url: the bot token is a path segment of it.
  The postern-email SECONDARY is blocked on fc#2093 and must not be declared before it can send.
  Both credentials are SECRETS because this repo is public and the
  topic name is the only thing protecting the channel.

## Documentation map

- `README.md` -- what it checks (uptime + posture), the alerting model, deploy, and follow-ups.
- Internal Gatus and the off-fleet dead-man monitor pair that used to own inside-fleet status
  posture are both gone (2026-09-24 teardown); this repo is CF-edge-only and was never the
  inside view. Half of the resulting doc/code mismatch is now closed: `config/monitors.json` was
  re-derived from live measurement on 2026-09-25 and no longer lists dead fleet surfaces.
  `README.md` is NOT closed; it still cites the "fleet Gatus vantage" as covering ground (three
  places), and correcting that prose is a follow-up this branch did not do.

## Commands

```bash
npm run typecheck   # tsc --noEmit: the CI gate, run before pushing
npm run test        # vitest unit tests (validate.ts)
npm run test:coverage
npm run dev         # wrangler dev --test-scheduled (drive the cron locally)
npm run deploy      # wrangler deploy
```

## Architecture

- **Cron-only.** Trigger is `*/5 * * * *`. `workers_dev` and `preview_urls` are off; the only
  route is the `monitor.skyphusion.org` custom domain so internal monitoring can poll `/health`.
- **Config-driven (monitor#42).** The probe inventory is `config/monitors.json` (CI-validated,
  bundled at build); tunables are `[vars]` with in-code defaults (`src/config.ts`).
  `src/index.ts` is the engine only -- adding a surface is a config edit, never a src/ edit,
  and an invalid inventory fails CLOSED (health RED + one deduped urgent alert, never a silent
  empty run).
- **Dead-man's-switch.** Each cron run writes its timestamp + counts to the `MONITOR_STATE` KV.
  `/health` returns 503 if the last run is stale (`HEALTH_STALE_MIN`, default 12m) or had failures.
- **Alerts are quiet-when-healthy.** Telegram only on failure; posture regressions marked urgent.

## Conventions

- **No em-dashes (U+2014) or en-dashes (U+2013) anywhere.** Use commas, semicolons,
  parentheses, or `--`.
- Handle / username is `skyphusion`.
- **Mirror every `wrangler.toml` binding in the hand-authored `Env`** (`src/env.ts`).
- `account_id` is never hardcoded; it comes from `CLOUDFLARE_ACCOUNT_ID`. Secrets via
  `wrangler secret put` only (never in tracked files).
- `npm run typecheck` + `npm run test:coverage` are CI gates.

## Commits & versioning

Conventional Commits (`feat(scope):`, `fix(scope):`, `docs:`); SemVer-style `0.MINOR.PATCH` while
pre-1.0; bump `package.json` `version` in the release commit.

## Release / deploy

**Tag-gated production deploy.** Merges to `main` run CI only; they do not ship production.
Cut an annotated SemVer tag on `main` to release (`git tag -a vX.Y.Z -m "..." && git push origin vX.Y.Z`).
Deploy workflows assert the tag commit is an ancestor of `origin/main`.
