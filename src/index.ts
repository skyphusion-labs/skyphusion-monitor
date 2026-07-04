// skyphusion-monitor: external security-posture + uptime checks from the CF edge.
// Probes the PUBLIC surfaces as an OUTSIDER and asserts both uptime AND security
// posture; alerts to ntfy ONLY on a failed assertion (quiet when healthy).
// The posture assertions encode tonights security pass (F1/F2/F4): "what an
// outsider should and should NOT be able to do." A regression fires before anyone
// can brag about it.
import type { Env } from "./env";

type Kind = "uptime" | "posture";
interface Check {
  name: string;
  url: string;
  ok: number[];                       // acceptable final status codes
  kind: Kind;
  note?: string;
  // optional: a body containing any of these (case-insensitive) is a FAILURE even
  // if the status matched (catches "200 but serving sensitive JSON" auth bypass).
  bodyMustNotInclude?: string[];
  // optional: required response headers (lowercased name -> expected value)
  requireHeaders?: Record<string, string>;
}

const WD = (w: string) => `https://${w}.skyphusion.workers.dev`;

const CHECKS: Check[] = [
  // ---------- uptime: public surfaces should serve ----------
  { name: "intro-apex",   url: "https://skyphusion.org/",        ok: [200, 301, 302, 308], kind: "uptime" },
  { name: "intro-www",    url: "https://www.skyphusion.org/",    ok: [200, 301, 302, 308], kind: "uptime" },
  { name: "blog",         url: "https://skyphusion.net/",        ok: [200, 301, 302, 308], kind: "uptime" },
  { name: "playground",   url: "https://play.skyphusion.org/",   ok: [200, 302], kind: "uptime",
    requireHeaders: { "x-content-type-options": "nosniff" } },   // F4: nosniff on our workers 200
  { name: "status-gatus", url: "https://status.skyphusion.org/", ok: [200, 302], kind: "uptime" },
  { name: "authentik",    url: "https://auth.skyphusion.org/",   ok: [200, 302], kind: "uptime" },
  { name: "ntfy",         url: "https://ntfy.skyphusion.org/",   ok: [200], kind: "uptime" },

  // ---------- F1: workers.dev must NOT serve app data unauthenticated ----------
  // vivijure had NO in-worker auth (edge-Access only), so workers_dev=true exposed
  // the whole /api. It is now disabled (404). Tripwire: if it flips back on -> CRITICAL.
  { name: "F1.vivijure-workersdev.cast",    url: `${WD("vivijure-studio")}/api/cast`,    ok: [404, 530, 1033], kind: "posture",
    bodyMustNotInclude: ["\"cast\"", "portrait_key"], note: "workers_dev must stay OFF; serving = F1 regression" },
  { name: "F1.vivijure-workersdev.modules", url: `${WD("vivijure-studio")}/api/modules`, ok: [404, 530, 1033], kind: "posture",
    bodyMustNotInclude: ["\"modules\"", "config_schema"], note: "workers_dev must stay OFF; serving = F1 regression" },
  { name: "F1.grid-hub-workersdev",         url: `${WD("grid-hub")}/`,                   ok: [404, 530, 1033], kind: "posture",
    note: "grid-hub is backend-only (reached by world Workers via service binding); workers.dev must stay OFF (fleet-chezmoi#46)" },

  // ---------- F2: Access must enforce on the vivijure custom domain ----------
  { name: "F2.vivijure-access.cast",    url: "https://vivijure.skyphusion.org/api/cast",    ok: [302, 401, 403], kind: "posture",
    bodyMustNotInclude: ["portrait_key", "\"bible\""], note: "302=Access-login / 401/403 = blocked (healthy); 200+data = Access opened up" },
  { name: "F2.vivijure-access.modules", url: "https://vivijure.skyphusion.org/api/modules", ok: [302, 401, 403], kind: "posture",
    bodyMustNotInclude: ["config_schema"], note: "anon must be Access-blocked; 200+data = Access opened up" },

  // ---------- F2-class: Access must enforce on chat-plus (openwebui-friends) ----------
  // Identity allow-list + trusted-email-header SSO (fleet-chezmoi fc#294): the origin
  // TRUSTS Cf-Access-Authenticated-User-Email, so the Access gate dropping = the friends
  // instance serving anonymously on Conrad's Unified Billing (denial-of-wallet surface).
  { name: "F2.chatplus-access", url: "https://chat-plus.skyphusion.org/", ok: [302, 401, 403], kind: "posture",
    bodyMustNotInclude: ["WebUI", "webui"], note: "302=Access-login (healthy, verified -> skyphusion.cloudflareaccess.com); 200/OpenWebUI markup = Access gate dropped" },

  // ---------- F2-class: Access must enforce on the remaining gated surfaces (monitor#17) ----------
  // Live CF Access app inventory diffed against CHECKS 2026-07-04; all three verified
  // answering the Access login 302 anonymously (body = the generic CF redirect page,
  // marker-free). play = an AI-spend surface (prism on Unified Billing), chat = the
  // free-tier OpenWebUI, status = the Gatus internal-topology view. The watt-soak hosts
  // (status-watt, grafana-watt) are deliberately NOT here: soak surfaces, fc#195.
  { name: "F2.play-access", url: "https://play.skyphusion.org/", ok: [302, 401, 403], kind: "posture",
    bodyMustNotInclude: ["system-prompt", "sidebar-backdrop"], note: "302=Access-login (healthy); 200/prism markup = Access gate dropped on an AI-spend surface" },
  { name: "F2.chat-access", url: "https://chat.skyphusion.org/", ok: [302, 401, 403], kind: "posture",
    bodyMustNotInclude: ["WebUI", "webui"], note: "302=Access-login (healthy); 200/OpenWebUI markup = Access gate dropped" },
  { name: "F2.status-access", url: "https://status.skyphusion.org/", ok: [302, 401, 403], kind: "posture",
    bodyMustNotInclude: ["Gatus", "gatus"], note: "302=Access-login (healthy); 200/Gatus markup = Access gate dropped, internal topology exposed" },

  // ---------- in-worker auth regression tripwires ----------
  // These workers self-authenticate (so workers.dev is not a bypass). Assert their
  // protected endpoints KEEP returning 401 -- a 200 here = an auth regression.
  { name: "AUTH.email-inbound.messages", url: `${WD("skyphusion-email-inbound")}/api/messages`, ok: [401, 403, 404], kind: "posture",
    bodyMustNotInclude: ["\"from\"", "\"subject\"", "\"body\""], note: "email API must require a token; 200 = mailbox exposure. 404 = workers.dev disabled (route gone), also healthy (fleet-chezmoi#46)" },
  { name: "AUTH.vivijure-search.root",   url: `${WD("vivijure-search")}/`,                    ok: [401, 403, 404], kind: "posture",
    note: "search worker must self-authenticate; 200+results = auth regression. 404 = workers.dev disabled (route gone), also healthy (fleet-chezmoi#46)" },
];

interface Result { name: string; kind: Kind; url: string; status: number | null; expected: number[]; ok: boolean; reason?: string; note?: string }

async function attemptCheck(c: Check): Promise<Result> {
  const ctrl = new AbortController();
  const t = setTimeout(() => ctrl.abort(), 12_000);
  try {
    const res = await fetch(c.url, { method: "GET", redirect: "manual", signal: ctrl.signal,
      headers: { "user-agent": "skyphusion-monitor/1 (+external posture probe)" } });
    let ok = c.ok.includes(res.status);
    let reason: string | undefined;
    if (!ok) reason = `status ${res.status} not in ${c.ok.join("/")}`;
    // header assertions (only meaningful on a real 2xx from our origin)
    if (ok && c.requireHeaders) {
      for (const [h, want] of Object.entries(c.requireHeaders)) {
        const got = res.headers.get(h);
        if (!got || got.toLowerCase() !== want.toLowerCase()) { ok = false; reason = `header ${h}=${got ?? "(absent)"} want ${want}`; }
      }
    }
    // body-content assertion (catch "matched status but leaked data")
    if (ok && c.bodyMustNotInclude && c.bodyMustNotInclude.length) {
      const body = await res.text().catch(() => "");
      const hit = c.bodyMustNotInclude.find(s => body.includes(s));
      if (hit) { ok = false; reason = `body leaked marker ${JSON.stringify(hit)}`; }
    }
    return { name: c.name, kind: c.kind, url: c.url, status: res.status, expected: c.ok, ok, reason, note: c.note };
  } catch (e) {
    return { name: c.name, kind: c.kind, url: c.url, status: null, expected: c.ok, ok: false, reason: String(e), note: c.note };
  } finally {
    clearTimeout(t);
  }
}
async function runCheck(c: Check): Promise<Result> {
  let r = await attemptCheck(c);
  if (!r.ok) { await new Promise(res => setTimeout(res, 1500)); r = await attemptCheck(c); } // retry once: tolerate a transient blip
  return r;
}
async function runAll(): Promise<Result[]> { return Promise.all(CHECKS.map(runCheck)); }

async function alert(env: Env, fails: Result[]): Promise<void> {
  if (!env.NTFY_TOKEN || !env.NTFY_URL || !env.MONITOR_TOPIC) return;
  const posture = fails.filter(f => f.kind === "posture");
  const title = posture.length
    ? `SECURITY: ${posture.length} posture regression(s)` + (fails.length > posture.length ? ` + ${fails.length - posture.length} uptime` : "")
    : `skyphusion: ${fails.length} surface(s) down`;
  const lines = fails.map(f =>
    `${f.kind === "posture" ? "[SEC] " : ""}${f.name}: ${f.reason ?? `status ${f.status}`} (want ${f.expected.join("/")})` +
    (f.note ? ` -- ${f.note}` : ""));
  await fetch(`${env.NTFY_URL}/${env.MONITOR_TOPIC}`, {
    method: "POST",
    headers: {
      Authorization: `Bearer ${env.NTFY_TOKEN}`,
      Title: title,
      Priority: posture.length ? "urgent" : "high",
      Tags: posture.length ? "rotating_light,lock" : "warning",
    },
    body: lines.join("\n"),
  });
}

async function recordRun(env: Env, results: Result[]): Promise<void> {
  const fails = results.filter(r => !r.ok);
  const postureFails = fails.filter(f => f.kind === "posture");
  await env.MONITOR_STATE.put("last-run",
    JSON.stringify({ ts: Date.now(), checks: results.length, failures: fails.length,
      posture: postureFails.length, failNames: fails.map(f => f.name) }),
    { expirationTtl: 86_400 });
}

// --- delivery dead-man (#278) --------------------------------------------------------------------
// The mail-relay dead-man address routes to this Worker. Any delivered mail proves the WHOLE
// outbound path worked (dischord cron -> msmtp -> relay.internal:2525 -> OpenDKIM sign ->
// direct-to-MX egress -> CF MX for skyphusion.org -> Email Routing -> here). We GET the HC.io
// check ping URL so HC.io does NOT page; if ANY hop breaks, no mail arrives, no ping, and HC.io
// fires after timeout(3600s)+grace(900s). Per-function key: this Worker holds ONLY the check's
// ping URL (HC_DEADMAN_PING_URL secret), NEVER the HC.io management key.
const DEADMAN_FROM = "noreply@skyphusion.org"; // the pusher's envelope sender (mail-relay-deadman.sh)

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
// when any ACTIVE cert is within CERT_WARN_DAYS of expires_on. Info-only on /health (no status
// flip: CF Universal SSL auto-renews ~30d out, and a fully-expired cert already fails the uptime
// probes -- this is the early-warning lane, not a pager). Per-function key: CF_CERT_READ_TOKEN
// is read-scoped (Zone Read + SSL and Certificates Read) and never the account admin token.
const CERT_WARN_DAYS = 14;
const CERT_CHECK_INTERVAL_MS = 20 * 60 * 60 * 1000; // ~daily; <24h so cron jitter can't skip a day

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

async function maybeCheckCerts(env: Env, now: number): Promise<void> {
  if (!env.CF_CERT_READ_TOKEN) return; // no-op until the secret is set
  const raw = await env.MONITOR_STATE.get("cert-check");
  if (raw && now - (JSON.parse(raw) as CertState).ts < CERT_CHECK_INTERVAL_MS) return;
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
          if (days <= CERT_WARN_DAYS) warnings.push(`${z.name}: TLS cert expires in ${days}d (${c.expires_on})`);
        }
      }
    }
    await env.MONITOR_STATE.put("cert-check",
      JSON.stringify({ ts: now, zones: zones.length, soonestDays, warned: warnings.length } satisfies CertState));
    if (warnings.length && env.NTFY_TOKEN && env.NTFY_URL && env.MONITOR_TOPIC) {
      await fetch(`${env.NTFY_URL}/${env.MONITOR_TOPIC}`, {
        method: "POST",
        headers: {
          Authorization: `Bearer ${env.NTFY_TOKEN}`,
          Title: `TLS: ${warnings.length} cert(s) near expiry`,
          Priority: "high",
          Tags: "warning,lock",
        },
        body: warnings.join("\n"),
      });
    }
  } catch (e) {
    // Record the failure (visible on /health) and let the next daily window retry; a broken
    // cert probe must not fail the run or page -- the surfaces themselves are still covered.
    await env.MONITOR_STATE.put("cert-check", JSON.stringify({ ts: now, error: String(e) } satisfies CertState));
  }
}

export default {
  async scheduled(_e: ScheduledEvent, env: Env, ctx: ExecutionContext): Promise<void> {
    const results = await runAll();
    const fails = results.filter(r => !r.ok);
    ctx.waitUntil(recordRun(env, results));
    if (fails.length) ctx.waitUntil(alert(env, fails));
    ctx.waitUntil(maybeCheckCerts(env, Date.now())); // monitor#3 part 2: daily-gated inside
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
    if (message.from !== DEADMAN_FROM) return;
    const url = env.HC_DEADMAN_PING_URL;
    // No-op until wired (secret unset); only ever GET the HC.io ping host (SSRF guard).
    if (!url || !url.startsWith("https://hc-ping.com/")) return;
    ctx.waitUntil(pingDeadman(url));
  },
  async fetch(req: Request, env: Env): Promise<Response> {
    const url = new URL(req.url);
    if (url.pathname === "/health") {
      // Gatus polls this: 200 = healthy, 503 = monitor stale (cron stopped = dead-man)
      // or the last run had failures. Counts only -- never leak check names.
      const raw = await env.MONITOR_STATE.get("last-run");
      const h: Record<string, unknown> = { service: "skyphusion-monitor", checks: CHECKS.length };
      if (!raw) return Response.json({ ...h, ok: false, reason: "no run recorded yet" }, { status: 503, headers: { "cache-control": "no-store" } });
      const last = JSON.parse(raw) as { ts: number; checks: number; failures: number; posture?: number };
      const ageMs = Date.now() - last.ts;
      const stale = ageMs > 12 * 60_000;
      const sick = (last.posture ?? last.failures) > 0;   // posture regression only
      const ok = !stale && !sick;
      // cert-expiry (monitor#3 part 2): INFO-ONLY, never flips /health status. Counts/days only,
      // no zone names (same never-leak-check-names rule as above).
      const certRaw = await env.MONITOR_STATE.get("cert-check");
      const cert = certRaw ? (() => { const c = JSON.parse(certRaw) as CertState;
        return { soonestDays: c.soonestDays ?? null, warned: c.warned ?? 0, probeError: !!c.error, ageSec: Math.round((Date.now() - c.ts) / 1000) }; })() : null;
      return Response.json({ ...h, ok, lastRunTs: last.ts, ageSec: Math.round(ageMs / 1000), failures: last.failures, posture: last.posture ?? 0, stale, sick, cert },
        { status: ok ? 200 : 503, headers: { "cache-control": "no-store" } });
    }
    if (url.pathname === "/run") {
      if (!env.RUN_KEY || url.searchParams.get("key") !== env.RUN_KEY) return new Response("forbidden", { status: 403 });
      const results = await runAll();
      const fails = results.filter(r => !r.ok);
      await recordRun(env, results);
      if (fails.length) await alert(env, fails);
      return Response.json({ failures: fails.length, results }, { headers: { "cache-control": "no-store" } });
    }
    return new Response("skyphusion-monitor", { status: 200 });
  },
};
