// skyphusion-monitor: external security-posture + uptime checks from the CF edge.
// Probes the PUBLIC surfaces as an OUTSIDER and asserts both uptime AND security
// posture; alerts to ntfy ONLY on a failed assertion (quiet when healthy).
//
// monitor#42: this file is the ENGINE only. The probe inventory lives in
// config/monitors.json (CI-validated, bundled at build); every operational knob
// is a wrangler var with a safe default (src/config.ts). No estate hostname or
// magic number belongs here.
import type { Env } from "./env";
import { loadChecks, tunables, type Tunables } from "./config";
import { assessResponse, type CheckConfig, type CheckKind } from "./validate";

interface Result { name: string; kind: CheckKind; url: string; status: number | null; expected: number[]; ok: boolean; reason?: string; note?: string }

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

async function pingDeadman(url: string): Promise<void> {
  const ctrl = new AbortController();
  const t = setTimeout(() => ctrl.abort(), 10_000);
  try {
    await fetch(url, {
      method: "GET",
      signal: ctrl.signal,
      headers: { "user-agent": "skyphusion-monitor/deadman (+delivery dead-man #278)" },
    });
  } catch {
    // swallow: a failed ping just means HC.io pages if it persists -- safe-fail, no throw.
  } finally {
    clearTimeout(t);
  }
}

// --- TLS cert-expiry probe (monitor#3 part 2) ------------------------------------------------
// Daily (KV-gated) sweep of every active zone's ssl/certificate_packs via the CF API; ntfy-warns
// when any ACTIVE cert is within certWarnDays of expires_on. Info-only on /health (no status
// flip: CF Universal SSL auto-renews ~30d out, and a fully-expired cert already fails the uptime
// probes -- this is the early-warning lane, not a pager). Per-function key: CF_CERT_READ_TOKEN
// is read-scoped (Zone Read + SSL and Certificates Read) and never the account admin token.

interface CertState { ts: number; zones?: number; soonestDays?: number | null; warned?: number; error?: string }

async function cfGet<T>(env: Env, path: string): Promise<T[]> {
  const res = await fetch(`https://api.cloudflare.com/client/v4${path}`, {
    headers: { Authorization: `Bearer ${env.CF_CERT_READ_TOKEN}`, "user-agent": "skyphusion-monitor/cert-expiry (+monitor#3)" },
  });
  if (!res.ok) throw new Error(`CF API ${path}: HTTP ${res.status}`);
  const j = await res.json() as { success: boolean; result: T[] | null };
  if (!j.success || !j.result) throw new Error(`CF API ${path}: success=false`);
  return j.result;
}

async function maybeCheckCerts(env: Env, t: Tunables, now: number): Promise<void> {
  if (!env.CF_CERT_READ_TOKEN) return; // no-op until the secret is set
  const raw = await env.MONITOR_STATE.get("cert-check");
  if (raw && now - (JSON.parse(raw) as CertState).ts < t.certCheckIntervalMs) return;
  try {
    const zones = await cfGet<{ id: string; name: string }>(env, "/zones?status=active&per_page=50");
    const warnings: string[] = [];
    let soonestDays: number | null = null;
    for (const z of zones) {
      const packs = await cfGet<{ status: string; certificates?: { expires_on?: string }[] }>(
        env, `/zones/${z.id}/ssl/certificate_packs`);
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

export default {
  async scheduled(_e: ScheduledEvent, env: Env, ctx: ExecutionContext): Promise<void> {
    const t = tunables(env);
    const { checks, errors } = loadChecks();
    if (errors.length) { await recordConfigFailure(env, errors); return; } // fail closed, no dead-man ping
    const results = await runAll(checks, t);
    const fails = results.filter(r => !r.ok);
    ctx.waitUntil(recordRun(env, results));
    if (fails.length) ctx.waitUntil(alert(env, fails));
    ctx.waitUntil(maybeCheckCerts(env, t, Date.now())); // monitor#3 part 2: daily-gated inside
    // scheduled dead-man (monitor#3 part 1): reaching here means the cron FIRED and the run
    // COMPLETED -> ping the HC.io check so it does not page. This signals MONITOR liveness,
    // NOT check health -- surface failures are already handled by alert()/ntfy + /health RED;
    // conflating them into the dead-man would double-page and muddy the 'is the monitor alive'
    // signal. No-op until the secret is set; only ever GET the hc-ping host (SSRF guard, same
    // as email()). If runAll() ever throws, scheduled() rejects BEFORE this -> no ping -> HC.io
    // pages, which is exactly right (the monitor broke).
    const cronPing = env.HC_CRON_PING_URL;
    if (cronPing && cronPing.startsWith('https://hc-ping.com/')) ctx.waitUntil(pingDeadman(cronPing));
  },
  async email(message: ForwardableEmailMessage, env: Env, ctx: ExecutionContext): Promise<void> {
    // Only the fleet pusher keeps the dead-man alive: defense-in-depth so a stray sender to
    // this (obscure) address cannot reset the timer and mask a real delivery outage.
    if (message.from !== tunables(env).deadmanFrom) return;
    const url = env.HC_DEADMAN_PING_URL;
    // No-op until wired (secret unset); only ever GET the HC.io ping host (SSRF guard).
    if (!url || !url.startsWith("https://hc-ping.com/")) return;
    ctx.waitUntil(pingDeadman(url));
  },
  async fetch(req: Request, env: Env): Promise<Response> {
    const t = tunables(env);
    const url = new URL(req.url);
    if (url.pathname === "/health") {
      // Gatus polls this: 200 = healthy, 503 = monitor stale (cron stopped = dead-man)
      // or the last run had failures. Counts only -- never leak check names.
      const { checks, errors } = loadChecks();
      const raw = await env.MONITOR_STATE.get("last-run");
      const h: Record<string, unknown> = { service: "skyphusion-monitor", checks: checks.length, configValid: !errors.length };
      if (!raw) return Response.json({ ...h, ok: false, reason: "no run recorded yet" }, { status: 503, headers: { "cache-control": "no-store" } });
      const last = JSON.parse(raw) as { ts: number; checks: number; failures: number; posture?: number; configError?: boolean };
      const ageMs = Date.now() - last.ts;
      const stale = ageMs > t.healthStaleMs;
      const sick = (last.posture ?? last.failures) > 0;   // posture regression only
      const ok = !stale && !sick;
      // cert-expiry (monitor#3 part 2): INFO-ONLY, never flips /health status. Counts/days only,
      // no zone names (same never-leak-check-names rule as above).
      const certRaw = await env.MONITOR_STATE.get("cert-check");
      const cert = certRaw ? (() => { const c = JSON.parse(certRaw) as CertState;
        return { soonestDays: c.soonestDays ?? null, warned: c.warned ?? 0, probeError: !!c.error, ageSec: Math.round((Date.now() - c.ts) / 1000) }; })() : null;
      return Response.json({ ...h, ok, lastRunTs: last.ts, ageSec: Math.round(ageMs / 1000), failures: last.failures, posture: last.posture ?? 0, stale, sick, configError: !!last.configError, cert },
        { status: ok ? 200 : 503, headers: { "cache-control": "no-store" } });
    }
    if (url.pathname === "/run") {
      if (!env.RUN_KEY || url.searchParams.get("key") !== env.RUN_KEY) return new Response("forbidden", { status: 403 });
      const { checks, errors } = loadChecks();
      if (errors.length) { await recordConfigFailure(env, errors); return Response.json({ configErrors: errors }, { status: 500 }); }
      const results = await runAll(checks, t);
      const fails = results.filter(r => !r.ok);
      await recordRun(env, results);
      if (fails.length) await alert(env, fails);
      return Response.json({ failures: fails.length, results }, { headers: { "cache-control": "no-store" } });
    }
    return new Response("skyphusion-monitor", { status: 200 });
  },
};
