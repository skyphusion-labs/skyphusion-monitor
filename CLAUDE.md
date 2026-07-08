# CLAUDE.md

Guidance for Claude Code (and the crew) working in this repo.

## What this is

An external **security-posture + uptime** monitor: a standalone Cloudflare Worker (cron, every
5 minutes) that probes the public skyphusion surfaces from CF's global edge -- a true
*outside-the-fleet* vantage and a **separate failure domain** from the Hetzner fleet and from
internal Gatus (inside view). It runs at `monitor.skyphusion.org` and was chosen over a US
Hetzner box (the retired nofx idea): $0, no box, no cross-zone networking.

> Note: this is NOT Gatus. Internal Gatus sees the inside view; `status.skyphusion.org` is
> Access-gated. This Worker is the complementary outside view; both alert via ntfy.

## Documentation map

- `README.md` -- what it checks (uptime + posture), the alerting model, deploy, and follow-ups.

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
- **Dead-man's-switch.** Each cron run writes its timestamp + counts to the `MONITOR_STATE` KV.
  `/health` returns 503 if the last run is stale (>12m) or had failures.
- **Alerts are quiet-when-healthy.** ntfy only on failure; posture regressions at `urgent`.

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
