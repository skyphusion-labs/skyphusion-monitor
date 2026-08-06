// skyphusion-monitor: external security-posture + uptime checks from the CF edge.
// Probes the PUBLIC surfaces as an OUTSIDER and asserts both uptime AND security
// posture; alerts to ntfy ONLY on a failed assertion (quiet when healthy).
//
// monitor#42: this file is the ENGINE only. The probe inventory lives in
// config/monitors.json (CI-validated, bundled at build); every operational knob
// is a wrangler var with a safe default (src/config.ts). No estate hostname or
// magic number belongs here.
import type { Env } from "./env";
import { loadChecks, loadWorkersDevPolicy, tunables, type Tunables } from "./config";
import { assessResponse, type CheckConfig, type CheckKind } from "./validate";
import { assessWorkersDevCoverage, coverageSignature, summarizeCoverage, type SubdomainState } from "./coverage";

interface Result { name: string; kind: CheckKind; url: string; status: number | null; expected: number[]; ok: boolean; reason?: string; note?: string }

/**
 * Derive /health `sick` from the last-run record.
 *
 * `ok`/`sick` mean "the board is clean" (what Gatus polls), not "posture-only".
 * Uptime failures must flip sick. The old form `(posture ?? failures) > 0` fails
 * that when posture is 0 and failures is N: `??` does not substitute for 0.
 * Issue #58.
 */
export function isSickFromLastRun(last: {
  failures: number;
  posture?: number;
  configError?: boolean;
}): boolean {
  return (last.failures ?? 0) > 0 || !!last.configError;
}

async function attemptCheck(c: CheckConfig, t: Tunables): Promise<Result> {
  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), c.timeoutMs ?? t.fetchTimeoutMs);
  try {
    const res = await fetch(c.url, { method: "GET", redirect: "manual", signal: ctrl.signal,
      headers: { "user-agent": t.userAgent } });
    // Read the body only when a marker assertion needs it.
    const body = c.bodyMustNotInclude?.length ? await res.text().catch(() => "") : "";
    const a = assessResponse(c, res.status, (h) => res.headers.get(h), body);
    return { name: c.name, kind: c.kind, url: c.url, status: res.status, expected: c.ok, ok: a.ok, reason: a.reason, note: c.note };
  } catch (e) {
    return { name: c.name, kind: c.kind, url: c.url, status: null, expected: c.ok, ok: false, reason: String(e), note: c.note };
  } finally {
    clearTimeout(timer);
  }
}
async function runCheck(c: CheckConfig, t: Tunables): Promise<Result> {
  let r = await attemptCheck(c, t);
  if (!r.ok) { await new Promise(res => setTimeout(res, t.retryDelayMs)); r = await attemptCheck(c, t); } // retry once: tolerate a transient blip
  return r;
}
async function runAll(checks: CheckConfig[], t: Tunables): Promise<Result[]> {
  return Promise.all(checks.map((c) => runCheck(c, t)));
}

async function notify(env: Env, title: string, body: string, urgent: boolean, tags: string): Promise<void> {
  if (!env.NTFY_TOKEN || !env.NTFY_URL || !env.MONITOR_TOPIC) return;
  await fetch(`${env.NTFY_URL}/${env.MONITOR_TOPIC}`, {
    method: "POST",
    headers: {
      Authorization: `Bearer ${env.NTFY_TOKEN}`,
      Title: title,
      Priority: urgent ? "urgent" : "high",
      Tags: tags,
    },
    body,
  });
}

async function alert(env: Env, fails: Result[]): Promise<void> {
  const posture = fails.filter(f => f.kind === "posture");
  const title = posture.length
    ? `SECURITY: ${posture.length} posture regression(s)` + (fails.length > posture.length ? ` + ${fails.length - posture.length} uptime` : "")
    : `skyphusion: ${fails.length} surface(s) down`;
  const lines = fails.map(f =>
    `${f.kind === "posture" ? "[SEC] " : ""}${f.name}: ${f.reason ?? `status ${f.status}`} (want ${f.expected.join("/")})` +
    (f.note ? ` -- ${f.note}` : ""));
  await notify(env, title, lines.join("\n"), posture.length > 0, posture.length ? "rotating_light,lock" : "warning");
}

async function recordRun(env: Env, results: Result[]): Promise<void> {
  const fails = results.filter(r => !r.ok);
  const postureFails = fails.filter(f => f.kind === "posture");
  await env.MONITOR_STATE.put("last-run",
    JSON.stringify({ ts: Date.now(), checks: results.length, failures: fails.length,
      posture: postureFails.length, failNames: fails.map(f => f.name),
      // Vantage surprises must self-diagnose from KV (the first #42 deploy
      // failed 2 checks with no way to see WHY without code archaeology).
      // Internal state only; /health still never exposes names or reasons.
      failReasons: fails.map(f => `${f.name}: ${f.reason ?? `status ${f.status}`}`) }),
    { expirationTtl: 86_400 });
}

// monitor#42 fail-closed: an invalid/missing probe inventory must never become a
// silent empty run. Record it (flips /health RED via posture=1) and page ONCE
// per window (KV-deduped) instead of every 5 minutes.
async function recordConfigFailure(env: Env, errors: string[]): Promise<void> {
  await env.MONITOR_STATE.put("last-run",
    JSON.stringify({ ts: Date.now(), checks: 0, failures: 1, posture: 1,
      failNames: ["config-invalid"], configError: true }),
    { expirationTtl: 86_400 });
  const already = await env.MONITOR_STATE.get("config-error-alerted");
  if (already) return;
  await env.MONITOR_STATE.put("config-error-alerted", "1", { expirationTtl: 21_600 });
  await notify(env, "skyphusion-monitor: probe config INVALID (fail-closed)",
    errors.join("\n"), true, "rotating_light,gear");
}

// --- delivery dead-man (#278) --------------------------------------------------------------------
// The mail-relay dead-man address routes to this Worker. Any delivered mail proves the WHOLE
// outbound path worked (fleet mail relay -> direct-to-MX egress -> CF MX for skyphusion.org ->
// Email Routing -> here). We GET the HC.io check ping URL so HC.io does NOT page; if ANY hop
// breaks, no mail arrives, no ping, and HC.io fires after timeout(3600s)+grace(900s). Per-function
// key: this Worker holds ONLY the check's ping URL (HC_DEADMAN_PING_URL secret), NEVER the HC.io
// management key. The allowed envelope sender is the DEADMAN_FROM var (mail-relay-deadman.sh).

/** Result of a dead-man GET (no secrets). Used for KV observability. */
type DeadmanPingResult = { ok: boolean; status?: number; err?: string };

async function pingDeadman(url: string): Promise<DeadmanPingResult> {
  // Secrets and env can carry trailing newlines/spaces from shell-to-file puts;
  // startsWith can still pass while fetch fails on a URL with \n (fc#1272).
  const clean = url.trim().replace(/\/+$/, ""); // trailing slash -> HC 400
  if (!clean.startsWith("https://hc-ping.com/")) {
    return { ok: false, err: "url-not-hc-ping" };
  }
  const ctrl = new AbortController();
  const t = setTimeout(() => ctrl.abort(), 10_000);
  try {
    // Plain GET. (A custom User-Agent was removed after Worker-side 403s; bare fetch
    // is what we need to keep working for both email and cron dead-men.)
    const res = await fetch(clean, { method: "GET", signal: ctrl.signal, redirect: "manual" });
    // HC returns 200 OK on success; anything else is a failed reset.
    if (res.ok) return { ok: true, status: res.status };
    // Capture a short body snippet (no secrets expected) so 403/400 is diagnosable.
    let snippet = "";
    try {
      snippet = (await res.text()).slice(0, 80).replace(/\s+/g, " ");
    } catch {
      /* ignore */
    }
    return { ok: false, status: res.status, err: snippet || `http-${res.status}` };
  } catch (e) {
    // swallow throw: a failed ping just means HC.io pages if it persists -- safe-fail.
    return { ok: false, err: e instanceof Error ? e.name : "fetch-failed" };
  } finally {
    clearTimeout(t);
  }
}

/** sha256 hex prefix of a string -- for secret shape compare without revealing values. */
async function sha12(s: string): Promise<string> {
  const buf = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(s));
  return [...new Uint8Array(buf)].map((b) => b.toString(16).padStart(2, "0")).join("").slice(0, 12);
}

/** scheduled()-side flush of email-path dead-man (fc#1272). Safe to call from fetch too. */
async function flushDeadmanEmailPending(env: Env): Promise<void> {
  const pending = await env.MONITOR_STATE.get("deadman-email-pending");
  if (!pending) return;
  const url = (env.HC_DEADMAN_PING_URL ?? "").trim().replace(/\/+$/, "");
  if (!url.startsWith("https://hc-ping.com/")) return;
  const ping = await pingDeadman(url);
  if (!ping.ok) {
    console.log("deadman scheduled flush: HC ping failed", ping);
    return; // leave pending so the next cron retries
  }
  await env.MONITOR_STATE.delete("deadman-email-pending");
  const prev = await env.MONITOR_STATE.get("deadman-email-last");
  let base: Record<string, unknown> = { ts: Date.now() };
  if (prev) {
    try {
      base = { ...JSON.parse(prev), ...base };
    } catch {
      /* ignore */
    }
  }
  await env.MONITOR_STATE.put(
    "deadman-email-last",
    JSON.stringify({
      ...base,
      pending: false,
      pingOk: true,
      pingStatus: ping.status ?? 200,
      pingVia: "scheduled",
      pingTs: Date.now(),
    }),
    { expirationTtl: 86_400 * 7 },
  );
}

/** Bare addr lowercased; strips `Name <addr>` wrappers. Empty in -> empty out. */
export function normalizeEmailAddr(s: string | null | undefined): string {
  if (!s) return "";
  let t = s.trim().toLowerCase();
  const m = t.match(/<([^>]+)>/);
  if (m) t = m[1].trim();
  return t;
}

// --- Cloudflare API helper ---------------------------------------------------------------------
// Shared by the cert-expiry probe and the workers.dev coverage sweep. Each caller passes its OWN
// per-function token; there is deliberately no ambient/default credential here.

interface CfEnvelope<T> { success: boolean; result: T | null; result_info?: { total_count?: number; page?: number; total_pages?: number } }

async function cfApi<T>(token: string, path: string, ua: string): Promise<CfEnvelope<T>> {
  const res = await fetch(`https://api.cloudflare.com/client/v4${path}`, {
    headers: { Authorization: `Bearer ${token}`, "user-agent": ua },
  });
  if (!res.ok) throw new Error(`CF API ${path}: HTTP ${res.status}`);
  const j = await res.json() as CfEnvelope<T>;
  if (!j.success || j.result === null || j.result === undefined) throw new Error(`CF API ${path}: success=false`);
  return j;
}

// --- TLS cert-expiry probe (monitor#3 part 2) ------------------------------------------------
// Daily (KV-gated) sweep of every active zone's ssl/certificate_packs via the CF API; ntfy-warns
// when any ACTIVE cert is within certWarnDays of expires_on. Info-only on /health (no status
// flip: CF Universal SSL auto-renews ~30d out, and a fully-expired cert already fails the uptime
// probes -- this is the early-warning lane, not a pager). Per-function key: CF_CERT_READ_TOKEN
// is read-scoped (Zone Read + SSL and Certificates Read) and never the account admin token.

interface CertState { ts: number; zones?: number; soonestDays?: number | null; warned?: number; error?: string }

const CERT_UA = "skyphusion-monitor/cert-expiry (+monitor#3)";

async function maybeCheckCerts(env: Env, t: Tunables, now: number): Promise<void> {
  if (!env.CF_CERT_READ_TOKEN) return; // no-op until the secret is set
  const raw = await env.MONITOR_STATE.get("cert-check");
  if (raw && now - (JSON.parse(raw) as CertState).ts < t.certCheckIntervalMs) return;
  try {
    const zones = (await cfApi<{ id: string; name: string }[]>(env.CF_CERT_READ_TOKEN, "/zones?status=active&per_page=50", CERT_UA)).result!;
    const warnings: string[] = [];
    let soonestDays: number | null = null;
    for (const z of zones) {
      const packs = (await cfApi<{ status: string; certificates?: { expires_on?: string }[] }[]>(
        env.CF_CERT_READ_TOKEN, `/zones/${z.id}/ssl/certificate_packs`, CERT_UA)).result!;
      for (const p of packs) {
        if (p.status !== "active") continue;
        for (const c of p.certificates ?? []) {
          if (!c.expires_on) continue;
          const days = Math.floor((Date.parse(c.expires_on) - now) / 86_400_000);
          if (soonestDays === null || days < soonestDays) soonestDays = days;
          if (days <= t.certWarnDays) warnings.push(`${z.name}: TLS cert expires in ${days}d (${c.expires_on})`);
        }
      }
    }
    await env.MONITOR_STATE.put("cert-check",
      JSON.stringify({ ts: now, zones: zones.length, soonestDays, warned: warnings.length } satisfies CertState));
    if (warnings.length) {
      await notify(env, `TLS: ${warnings.length} cert(s) near expiry`, warnings.join("\n"), false, "warning,lock");
    }
  } catch (e) {
    // Record the failure (visible on /health) and let the next daily window retry; a broken
    // cert probe must not fail the run or page -- the surfaces themselves are still covered.
    await env.MONITOR_STATE.put("cert-check", JSON.stringify({ ts: now, error: String(e) } satisfies CertState));
  }
}

// --- workers.dev coverage sweep (fc#1194 / fc#1180 F2) -----------------------------------------
// The one check in this Worker that is NOT a probe, because it CANNOT be one: Cloudflare answers
// 404 `error code: 1042` for every sibling *.workers.dev subrequest, enabled and disabled alike
// (measured, see config/monitors.json $comment and src/coverage.ts). So the Worker LIST and the
// workers.dev state both come from the API, which makes coverage DERIVED: a Worker deployed
// tomorrow is assessed the moment it exists rather than waiting for someone to remember it.
//
// Every failure mode here is LOUD. Missing credential, HTTP error, success-with-zero-results,
// truncated enumeration, non-boolean state: all of them FAIL the posture check. There is no
// path where this degrades to a quiet skip, because a quiet skip is indistinguishable from
// "nothing is exposed", which is the exact defect this replaces.

interface CoverageState {
  ts: number;
  ok: boolean;
  scripts: number;
  allowed: number;
  enabled: number;
  sig: string;
  /** Human summary INCLUDING script names -- internal (KV, ntfy, gated /run) only, never /health. */
  summary: string;
  error?: string;
}

const COVERAGE_UA = "skyphusion-monitor/workers-dev-coverage (+fc#1194)";
const COVERAGE_KEY = "workersdev-coverage";
const COVERAGE_CHECK_NAME = "COVER.workers-dev";
// Bound concurrent subrequests; the sweep is 1 + N calls and N grows with the account.
const COVERAGE_BATCH = 8;

async function sweepWorkersDev(env: Env, now: number): Promise<CoverageState> {
  const { policy, errors } = loadWorkersDevPolicy();
  if (errors.length) throw new Error(`workersDev policy invalid: ${errors.join("; ")}`);

  const list = await cfApi<{ id?: string }[]>(env.CF_WORKERS_READ_TOKEN, `/accounts/${env.CF_ACCOUNT_ID}/workers/scripts`, COVERAGE_UA);
  const names = (list.result ?? []).map((s) => s.id).filter((n): n is string => typeof n === "string" && n.length > 0).sort();
  // A paginated list read with no total_count check is a truncated census. This endpoint does
  // not paginate today; assert that rather than assume it forever.
  const total = list.result_info?.total_count;
  if (typeof total === "number" && total > names.length) {
    throw new Error(`worker enumeration truncated: total_count ${total} > ${names.length} returned`);
  }

  const states: SubdomainState[] = [];
  for (let i = 0; i < names.length; i += COVERAGE_BATCH) {
    const batch = names.slice(i, i + COVERAGE_BATCH);
    states.push(...await Promise.all(batch.map(async (name): Promise<SubdomainState> => {
      const r = await cfApi<{ enabled?: unknown; previews_enabled?: unknown }>(
        env.CF_WORKERS_READ_TOKEN,
        `/accounts/${env.CF_ACCOUNT_ID}/workers/scripts/${encodeURIComponent(name)}/subdomain`,
        COVERAGE_UA);
      // Coercing a missing field to false would invent the reassuring answer. Refuse instead.
      if (typeof r.result?.enabled !== "boolean") throw new Error(`${name}: subdomain.enabled is not a boolean`);
      const previews = r.result?.previews_enabled;
      return { script: name, enabled: r.result.enabled, previewsEnabled: typeof previews === "boolean" ? previews : null };
    })));
  }

  const findings = assessWorkersDevCoverage(states, policy);
  return {
    ts: now,
    ok: findings.length === 0,
    scripts: states.length,
    allowed: policy.allowed.length,
    enabled: states.filter((s) => s.enabled).length,
    sig: coverageSignature(findings),
    summary: summarizeCoverage(findings, states.length),
  };
}

/**
 * Returns the current verdict, refreshing it at most once per sweep interval.
 * `alertable` is true only on a run that actually re-swept, so a STANDING failure pages hourly
 * instead of every 5 minutes while /health stays RED continuously.
 */
async function coverageVerdict(env: Env, t: Tunables, now: number): Promise<{ state: CoverageState; alertable: boolean }> {
  const raw = await env.MONITOR_STATE.get(COVERAGE_KEY);
  const prev = raw ? JSON.parse(raw) as CoverageState : null;
  if (prev && now - prev.ts < t.workersDevSweepIntervalMs) return { state: prev, alertable: false };

  let next: CoverageState;
  if (!env.CF_WORKERS_READ_TOKEN || !env.CF_ACCOUNT_ID) {
    // NOT a no-op. An absent credential means the state is unmeasured, and unmeasured is not clean.
    next = { ts: now, ok: false, scripts: 0, allowed: 0, enabled: 0, sig: "credential-missing",
      summary: "CF_WORKERS_READ_TOKEN / CF_ACCOUNT_ID unset -- workers.dev state UNMEASURED, not clean",
      error: "coverage credential unset" };
  } else {
    try {
      next = await sweepWorkersDev(env, now);
    } catch (e) {
      next = { ts: now, ok: false, scripts: 0, allowed: 0, enabled: 0, sig: "sweep-error",
        summary: `workers.dev coverage sweep FAILED: ${String(e)}`, error: String(e) };
    }
  }
  await env.MONITOR_STATE.put(COVERAGE_KEY, JSON.stringify(next), { expirationTtl: 86_400 });
  return { state: next, alertable: !next.ok };
}

/** Project the stored verdict into the run's result set, so /health and alerts both see it. */
function coverageResult(state: CoverageState | null, t: Tunables, now: number): Result {
  const base = { name: COVERAGE_CHECK_NAME, kind: "posture" as CheckKind,
    url: "https://api.cloudflare.com/client/v4/accounts/.../workers/scripts", status: null, expected: [] as number[] };
  if (!state) {
    return { ...base, ok: false, reason: "no workers.dev coverage verdict recorded yet -- state UNKNOWN, not clean" };
  }
  // Dead-man for the sweep itself: a verdict that stopped refreshing is not a passing verdict.
  if (now - state.ts > t.workersDevStaleMs) {
    return { ...base, ok: false, reason: `coverage verdict is STALE (${Math.round((now - state.ts) / 60_000)}m old) -- state UNKNOWN, not clean` };
  }
  return { ...base, ok: state.ok, reason: state.ok ? undefined : state.summary,
    note: state.ok ? undefined : "workers.dev is not covered by Access; see config/monitors.json workersDev" };
}

export default {
  async scheduled(_e: ScheduledEvent, env: Env, ctx: ExecutionContext): Promise<void> {
    const t = tunables(env);
    const { checks, errors } = loadChecks();
    const { errors: policyErrors } = loadWorkersDevPolicy();
    const configErrors = [...errors, ...policyErrors];
    if (configErrors.length) { await recordConfigFailure(env, configErrors); return; } // fail closed, no dead-man ping
    const now = Date.now();
    // Awaited, not waitUntil: its verdict is part of THIS run's result set.
    const coverage = await coverageVerdict(env, t, now);
    const results = [...await runAll(checks, t), coverageResult(coverage.state, t, now)];
    const fails = results.filter(r => !r.ok);
    const alertFails = fails.filter(f => f.name !== COVERAGE_CHECK_NAME || coverage.alertable);
    ctx.waitUntil(recordRun(env, results));
    if (alertFails.length) ctx.waitUntil(alert(env, alertFails));
    ctx.waitUntil(maybeCheckCerts(env, t, now)); // monitor#3 part 2: daily-gated inside
    // scheduled dead-man (monitor#3 part 1): reaching here means the cron FIRED and the run
    // COMPLETED -> ping the HC.io check so it does not page. This signals MONITOR liveness,
    // NOT check health -- surface failures are already handled by alert()/ntfy + /health RED;
    // conflating them into the dead-man would double-page and muddy the 'is the monitor alive'
    // signal. No-op until the secret is set; only ever GET the hc-ping host (SSRF guard, same
    // as email()). If runAll() ever throws, scheduled() rejects BEFORE this -> no ping -> HC.io
    // pages, which is exactly right (the monitor broke).
    const cronPing = env.HC_CRON_PING_URL;
    if (cronPing && cronPing.startsWith('https://hc-ping.com/')) ctx.waitUntil(pingDeadman(cronPing));
    // fc#1272: delivery dead-man HC ping runs HERE, not in email(). See email() comment.
    ctx.waitUntil(flushDeadmanEmailPending(env));
  },
  async email(message: ForwardableEmailMessage, env: Env, ctx: ExecutionContext): Promise<void> {
    // Only the fleet pusher keeps the dead-man alive: defense-in-depth so a stray sender to
    // this (obscure) address cannot reset the timer and mask a real delivery outage.
    // Normalize From: CF may pass envelope MAIL FROM bare, lower/upper, or "Name <addr>".
    // Measured silent-fail (fleet-chezmoi#1272): msmtp+postfix 250 every 5 min to CF MX and
    // Email Routing still pointed here, but HC last_ping stuck -- first From-gate (#68),
    // then HC_DEADMAN_PING_URL trailing-newline / failed fetch with no observability.
    const wantFrom = normalizeEmailAddr(tunables(env).deadmanFrom);
    const envelopeFrom = normalizeEmailAddr(message.from);
    const headerFrom = normalizeEmailAddr(message.headers.get("from"));
    const fromOk = !!wantFrom && (envelopeFrom === wantFrom || headerFrom === wantFrom);
    if (!fromOk) {
      // Loud enough for wrangler tail; no PII beyond what the routing already carried.
      console.log("deadman email: refuse from gate", { envelopeFrom, headerFrom, wantFrom });
      return;
    }
    const url = (env.HC_DEADMAN_PING_URL ?? "").trim();
    // No-op until wired (secret unset); only ever GET the HC.io ping host (SSRF guard).
    if (!url || !url.startsWith("https://hc-ping.com/")) {
      console.log("deadman email: refuse bad or unset HC_DEADMAN_PING_URL", {
        set: !!env.HC_DEADMAN_PING_URL,
        len: (env.HC_DEADMAN_PING_URL ?? "").length,
      });
      return;
    }
    // CRITICAL (fc#1272): do NOT call hc-ping.com from email() (or any nested fetch
    // spawned by email(), including service bindings). Measured 2026-08-06:
    //   - email() -> hc-ping.com: 403 "Blocked, see .../ru-ip-block/"
    //   - email() -> public monitor URL: 522
    //   - fetch()/scheduled() -> same secret URL: 200
    // Email-event colos egress via IPs Healthchecks classifies as blocked. Mark
    // pending; scheduled() (every 5 min) performs the real GET. Max lag ~= cron.
    console.log("deadman email: accept, pending scheduled HC ping", {
      to: normalizeEmailAddr(message.to),
    });
    ctx.waitUntil(
      (async () => {
        await env.MONITOR_STATE.put("deadman-email-pending", "1", { expirationTtl: 7_200 });
        await env.MONITOR_STATE.put(
          "deadman-email-last",
          JSON.stringify({
            ts: Date.now(),
            from: envelopeFrom || headerFrom,
            to: normalizeEmailAddr(message.to),
            pending: true,
          }),
          { expirationTtl: 86_400 * 7 },
        );
      })(),
    );
  },
  async fetch(req: Request, env: Env): Promise<Response> {
    const t = tunables(env);
    const url = new URL(req.url);
    if (url.pathname === "/health") {
      // Gatus polls this: 200 = healthy, 503 = monitor stale (cron stopped = dead-man)
      // or the last run had failures. Counts only -- never leak check names.
      const { checks, errors } = loadChecks();
      const { errors: policyErrors } = loadWorkersDevPolicy();
      const raw = await env.MONITOR_STATE.get("last-run");
      const h: Record<string, unknown> = { service: "skyphusion-monitor", checks: checks.length, configValid: !errors.length && !policyErrors.length };
      if (!raw) return Response.json({ ...h, ok: false, reason: "no run recorded yet" }, { status: 503, headers: { "cache-control": "no-store" } });
      const last = JSON.parse(raw) as { ts: number; checks: number; failures: number; posture?: number; configError?: boolean };
      const ageMs = Date.now() - last.ts;
      const stale = ageMs > t.healthStaleMs;
      // Gatus polls ok/sick. Any check failure (uptime OR posture) must flip the board;
      // posture alone is wrong: `(posture ?? failures)` stays 0 when posture is 0 and
      // failures is 2 (?? only substitutes for null/undefined). Issue #58 / fc#1194 theme.
      const sick = isSickFromLastRun(last);
      const ok = !stale && !sick;
      // cert-expiry (monitor#3 part 2): INFO-ONLY, never flips /health status. Counts/days only,
      // no zone names (same never-leak-check-names rule as above).
      const certRaw = await env.MONITOR_STATE.get("cert-check");
      const cert = certRaw ? (() => { const c = JSON.parse(certRaw) as CertState;
        return { soonestDays: c.soonestDays ?? null, warned: c.warned ?? 0, probeError: !!c.error, ageSec: Math.round((Date.now() - c.ts) / 1000) }; })() : null;
      // workers.dev coverage (fc#1194): COUNTS + verdict only. The summary names scripts, so it
      // stays out of this response exactly like check names and zone names do.
      const covRaw = await env.MONITOR_STATE.get(COVERAGE_KEY);
      const coverage = covRaw ? (() => { const c = JSON.parse(covRaw) as CoverageState;
        return { ok: c.ok, scripts: c.scripts, allowed: c.allowed, enabled: c.enabled, probeError: !!c.error,
          ageSec: Math.round((Date.now() - c.ts) / 1000) }; })() : null;
      return Response.json({ ...h, ok, lastRunTs: last.ts, ageSec: Math.round(ageMs / 1000), failures: last.failures, posture: last.posture ?? 0, stale, sick, configError: !!last.configError, cert, coverage },
        { status: ok ? 200 : 503, headers: { "cache-control": "no-store" } });
    }
    // fc#1272: HC ping from fetch context (email() cannot hit hc-ping.com -- RU-IP block
    // on email-event egress). Gated by x-deadman-relay = sha12(HC_DEADMAN_PING_URL); knowing
    // the header without the ping URL is useless, and knowing the URL already allows pings.
    if (url.pathname === "/internal/deadman-hc-ping" && req.method === "POST") {
      const raw = (env.HC_DEADMAN_PING_URL ?? "").trim().replace(/\/+$/, "");
      if (!raw) return Response.json({ ok: false, err: "unset" }, { status: 503 });
      const want = await sha12(raw);
      if (req.headers.get("x-deadman-relay") !== want) {
        return new Response("forbidden", { status: 403 });
      }
      const ping = await pingDeadman(raw);
      return Response.json(ping, { headers: { "cache-control": "no-store" } });
    }
    if (url.pathname === "/run") {
      if (!env.RUN_KEY || url.searchParams.get("key") !== env.RUN_KEY) return new Response("forbidden", { status: 403 });
      const { checks, errors } = loadChecks();
      const { errors: policyErrors } = loadWorkersDevPolicy();
      const configErrors = [...errors, ...policyErrors];
      if (configErrors.length) { await recordConfigFailure(env, configErrors); return Response.json({ configErrors }, { status: 500 }); }
      const now = Date.now();
      const coverage = await coverageVerdict(env, t, now);
      const results = [...await runAll(checks, t), coverageResult(coverage.state, t, now)];
      const fails = results.filter(r => !r.ok);
      const alertFails = fails.filter(f => f.name !== COVERAGE_CHECK_NAME || coverage.alertable);
      await recordRun(env, results);
      if (alertFails.length) await alert(env, alertFails);
      return Response.json({ failures: fails.length, results }, { headers: { "cache-control": "no-store" } });
    }
    return new Response("skyphusion-monitor", { status: 200 });
  },
};
