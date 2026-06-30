# CLAUDE.md

Guidance for Claude Code (and the crew) working in this repo.

## What this is

An external **security-posture + uptime** monitor: a standalone Cloudflare Worker (cron, every
5 minutes) that probes the public skyphusion surfaces from CF's global edge -- a true
*outside-the-fleet* vantage and a **separate failure domain** from the Hetzner fleet and from
Gatus-on-dischord (which sees the inside view). It runs at `monitor.skyphusion.org` and was
chosen over a US Hetzner box (the retired nofx idea): $0, no box, no cross-zone networking.
Currently **v0.1.0**.

> Note: this is NOT Gatus. Gatus is the inside-view monitor on dischord (the `monitoring` stack
> in `swarm-iac`, config in `fleet-chezmoi`, at `status.skyphusion.org`). This Worker is the
> complementary outside view; both alert via ntfy.

## Documentation map

- `README.md` -- what it checks (uptime + posture), the alerting model, deploy, and the v2
  follow-ups (TLS cert-expiry, healthchecks.io dead-man's-switch, wider posture checks).

## Commands

```bash
npm run typecheck   # tsc --noEmit: the CI gate, run before pushing
npm run dev         # wrangler dev --test-scheduled (drive the cron locally)
npm run deploy      # wrangler deploy
```

There is no unit suite; verify by running `npm run dev --test-scheduled` and exercising the
cron path plus the `/health` endpoint, after `npm run typecheck` is green.

## Architecture

- **Cron-only.** Trigger is `*/5 * * * *`. `workers_dev` and `preview_urls` are off; the only
  route is the `monitor.skyphusion.org` custom domain so Gatus can poll `/health`. The fetch
  handler (`/health`, gated `/run?key=`) is otherwise off the public internet.
- **Dead-man's-switch.** Each cron run writes its timestamp + counts to the `MONITOR_STATE` KV.
  `/health` returns 503 if the last run is stale (>12m) or had failures, so Gatus goes RED if
  this Worker itself dies.
- **Alerts are quiet-when-healthy.** It publishes to ntfy (`MONITOR_TOPIC` on `NTFY_URL`) only
  when a check fails its expectation; posture regressions go out at `urgent` priority.
- **Posture assertions are the point.** Anonymous edge fetches must see the expected status, or
  it fires as a SECURITY regression: `vivijure.skyphusion.org/api/*` must answer 401/403 (a 200
  means the CF Access gate dropped), and `vivijure-studio.skyphusion.workers.dev/api/*` must
  answer 404 -- the F1 tripwire that fires if `workers_dev` is ever re-enabled and reopens the
  unauthenticated backdoor.

## Conventions

- **No em-dashes (U+2014) or en-dashes (U+2013) anywhere.** Use commas, semicolons,
  parentheses, or `--`.
- Handle / username is `skyphusion`.
- **Mirror every `wrangler.toml` binding in the hand-authored `Env`** (`src/env.ts`). Do not
  generate `worker-configuration.d.ts`; runtime types come from the pinned
  `@cloudflare/workers-types` devDep.
- `account_id` is never hardcoded; it comes from `CLOUDFLARE_ACCOUNT_ID`. `NTFY_TOKEN` is a
  least-privilege ntfy publish token set via `wrangler secret put NTFY_TOKEN` (never in a
  tracked file).
- Minimal runtime deps; no framework, no build step beyond TypeScript.
- `npm run typecheck` is the gate; it must pass before pushing (`tsc` is not part of any test
  run).

## Crew + identity

- The first command in any op is the member's own login shell:
  `sudo -u <member> bash -lc '<ops>'` (own `$HOME`, own `~/dev/skyphusion-monitor` clone, own
  gh/CF creds). Crew commits land under the member's own `skyphusion-<member>` identity, never Conrad's.
  (Conrad devs ONLY on his laptop, where his commits author as
  `Conrad Rockenhaus <conrad@skyphusion.org>` -- his real name kept, the in-house
  `@skyphusion.org` email; his name is never scrubbed and his history never rewritten. On jello
  the `conrad` user is the god process and commits as `Mackaye <mackaye@skyphusion.org>`.)
- Fleet/infra operating memory lives under
  `~/.claude/projects/-home-conrad-dev-fleet-chezmoi/memory/` (Gatus migration, CF account
  inventory, ntfy topic); load it before acting.

## Commits & versioning

Conventional Commits (`feat(scope):`, `fix(scope):`, `docs:`); body explains the why. SemVer-style
`0.MINOR.PATCH` while pre-1.0 (PATCH for fixes / posture tweaks, MINOR for new checks); bump
`package.json` `version` in the release commit.
