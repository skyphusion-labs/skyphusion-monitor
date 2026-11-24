# skyphusion-monitor

This file is the guide for any coding agent and any contributor. Follow it.

## What this project is

skyphusion-monitor is a Cloudflare Worker that probes public HTTPS endpoints. The cron runs every 5 minutes. The probe list is config, not source. Read [README.md](README.md) and `config/monitors.json`.

The version is in `package.json`. See the latest `v*` tag.

## Commands

```bash
npm run typecheck
npm test
npm run test:coverage
npm run dev
npm run deploy
```

`npm run typecheck` is `tsc --noEmit`. Run it before you push. `tsc` does not run inside Vitest. [`.github/workflows/ci.yml`](.github/workflows/ci.yml) runs typecheck. [`.github/workflows/coverage.yml`](.github/workflows/coverage.yml) runs `npm test`.

`npm run dev` is `wrangler dev --test-scheduled`. `npm run deploy` publishes the Worker. Set `CLOUDFLARE_ACCOUNT_ID`. Production publish from CI is a `v*` tag. See [`.github/workflows/deploy.yml`](.github/workflows/deploy.yml). The tag commit must be on `main`. A merge to `main` leaves the live Worker unchanged.

## Architecture

The cron is `*/5 * * * *`. The public hostname is the custom domain in `wrangler.toml`. Adding a surface is an edit to `config/monitors.json`. Do not hardcode the surface list in source. An invalid inventory fails closed.

Each run writes a timestamp and counts to the `MONITOR_STATE` KV binding. `/health` returns 503 when the last run is stale or had failures. The stale window default is in `src/config.ts`.

Alerts fire when a probe fails. A healthy run stays quiet. Alert settings are in the README and in `wrangler.toml`. A missing alert credential fails `/health`. Do not log a URL that carries a token.

Read the expected HTTP status from `config/monitors.json`. Do not assume every host returns the same anonymous code. Add a hostname only after you resolve it and probe it. A check on a dead name hides a real outage.

A route in `wrangler.toml` does not prove the hostname resolves. Check DNS, `GET /health`, and the deploy run for the latest `v*` tag.

## Conventions

Mirror every `wrangler.toml` binding in `src/env.ts`. Do not hardcode `account_id`. Set secrets with `wrangler secret put`. Do not commit a secret.

## Docs

Write Simplified Technical English. Use short sentences. Use one idea per sentence. Use the active present tense. Use plain words. Use the same word every time.

Do not use an em dash (U+2014). Do not use an en dash (U+2013). Use a comma, a semicolon, parentheses, or two hyphens (`--`).

State the limit next to the capability. Do not turn a measured result into a promise.

## Safety

Do not put a secret in a tracked file, a log, or an issue. Use `npm run dev` to exercise the cron locally.

## Commits and versions

Use Conventional Commits. The body says why. A version moves only in a release pull request. The tag shape is `v*`. Feature work does not bump `package.json`. Fix work does not bump `package.json`.

The public handle is `skyphusion`.
