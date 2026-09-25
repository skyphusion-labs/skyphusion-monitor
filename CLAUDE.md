# CLAUDE.md

Guidance for Claude Code (and the crew) working in this repo.

## What this is

An external **security-posture + uptime** monitor: a standalone Cloudflare Worker (cron, every
5 minutes) that probes the public skyphusion surfaces from CF's global edge. It runs at
`monitor.skyphusion.org`: $0, no dedicated box, no cross-zone networking. It was designed as a
**separate failure domain** from the self-hosted Hetzner fleet and from internal Gatus (inside
view); both are gone as of 2026-09-24 (fleet decommissioned entirely, self-hosted Gatus with
it -- `status.skyphusion.org` still resolves at Cloudflare but the origin behind it errors 530,
confirmed live 2026-09-25). This repo's own `config/monitors.json` and `README.md` have not
caught up (last commit 2026-09-10): they still probe `status.skyphusion.org` and treat a "fleet
Gatus vantage" as a live counterpart. Separately, `monitor.skyphusion.org` itself does not
currently resolve (NXDOMAIN, checked 2026-09-25) despite `wrangler.toml` defining that route --
this repo's own deploy state needs re-verifying, not assumed from this doc.

> Note: this is NOT Gatus and was never meant to replace it, and it is not confirmed to be
> covering Gatus's old ground now either. Whatever plays the inside-fleet status role today, if
> anything, is unverified here; do not assume this Worker fills that gap. (The old claim that
> internal Gatus was "Access-gated" was also wrong independent of the fleet teardown:
> `config/monitors.json` documents `status.skyphusion.org` as intentionally public, gating only
> the push API.)

## Posture notes agents get wrong

- **Most F2 Access-gate checks** expect anonymous `302` / `401` / `403` (gate healthy).
- **`F2.play-public` is the opposite:** `https://play.skyphusion.org/` expects **`200`**. Prism is
  `AUTH_MODE=public` (first-party signup + mandatory per-user BYOK); Access was retired on play.
  Treating play as Access-gated is a defect in the inventory, not a prod outage.
- Probe inventory lives in `config/monitors.json` (config-driven; see README). Do not hardcode a
  surface list in source.

## Documentation map

- `README.md` -- what it checks (uptime + posture), the alerting model, deploy, and follow-ups.
- Internal Gatus and the off-fleet dead-man monitor pair that used to own inside-fleet status
  posture are both gone (2026-09-24 teardown); this repo is CF-edge-only and was never the
  inside view. The resulting doc/code mismatch in `README.md` / `config/monitors.json` is not
  yet resolved.

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

## Release / deploy

**Tag-gated production deploy.** Merges to `main` run CI only; they do not ship production.
Cut an annotated SemVer tag on `main` to release (`git tag -a vX.Y.Z -m "..." && git push origin vX.Y.Z`).
Deploy workflows assert the tag commit is an ancestor of `origin/main`.
