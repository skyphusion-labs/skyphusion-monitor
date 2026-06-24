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
  { name: "status-gatus", url: "https://status.skyphusion.org/", ok: [200], kind: "uptime" },
  { name: "authentik",    url: "https://auth.skyphusion.org/",   ok: [200, 302], kind: "uptime" },
  { name: "ntfy",         url: "https://ntfy.skyphusion.org/",   ok: [200], kind: "uptime" },

  // ---------- F1: workers.dev must NOT serve app data unauthenticated ----------
  // vivijure had NO in-worker auth (edge-Access only), so workers_dev=true exposed
  // the whole /api. It is now disabled (404). Tripwire: if it flips back on -> CRITICAL.
  { name: "F1.vivijure-workersdev.cast",    url: `${WD("vivijure-studio")}/api/cast`,    ok: [404, 530, 1033], kind: "posture",
    bodyMustNotInclude: ["\"cast\"", "portrait_key"], note: "workers_dev must stay OFF; serving = F1 regression" },
  { name: "F1.vivijure-workersdev.modules", url: `${WD("vivijure-studio")}/api/modules`, ok: [404, 530, 1033], kind: "posture",
    bodyMustNotInclude: ["\"modules\"", "config_schema"], note: "workers_dev must stay OFF; serving = F1 regression" },

  // ---------- F2: Access must enforce on the vivijure custom domain ----------
  { name: "F2.vivijure-access.cast",    url: "https://vivijure.skyphusion.org/api/cast",    ok: [401, 403], kind: "posture",
    bodyMustNotInclude: ["portrait_key", "\"bible\""], note: "anon must be Access-blocked; 200+data = Access opened up" },
  { name: "F2.vivijure-access.modules", url: "https://vivijure.skyphusion.org/api/modules", ok: [401, 403], kind: "posture",
    bodyMustNotInclude: ["config_schema"], note: "anon must be Access-blocked; 200+data = Access opened up" },

  // ---------- in-worker auth regression tripwires ----------
  // These workers self-authenticate (so workers.dev is not a bypass). Assert their
  // protected endpoints KEEP returning 401 -- a 200 here = an auth regression.
  { name: "AUTH.email-inbound.messages", url: `${WD("skyphusion-email-inbound")}/api/messages`, ok: [401, 403], kind: "posture",
    bodyMustNotInclude: ["\"from\"", "\"subject\"", "\"body\""], note: "email API must require a token; 200 = mailbox exposure" },
  { name: "AUTH.vivijure-search.root",   url: `${WD("vivijure-search")}/`,                    ok: [401, 403, 404], kind: "posture",
    note: "search worker must self-authenticate; 200+results = auth regression" },
];

interface Result { name: string; kind: Kind; url: string; status: number | null; expected: number[]; ok: boolean; reason?: string; note?: string }

async function runCheck(c: Check): Promise<Result> {
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

export default {
  async scheduled(_e: ScheduledEvent, env: Env, ctx: ExecutionContext): Promise<void> {
    const results = await runAll();
    const fails = results.filter(r => !r.ok);
    if (fails.length) ctx.waitUntil(alert(env, fails));
  },
  async fetch(req: Request, env: Env): Promise<Response> {
    const url = new URL(req.url);
    if (url.pathname === "/health")
      return Response.json({ service: "skyphusion-monitor", checks: CHECKS.length, topic: env.MONITOR_TOPIC });
    if (url.pathname === "/run") {
      if (!env.RUN_KEY || url.searchParams.get("key") !== env.RUN_KEY) return new Response("forbidden", { status: 403 });
      const results = await runAll();
      const fails = results.filter(r => !r.ok);
      if (fails.length) await alert(env, fails);
      return Response.json({ failures: fails.length, results }, { headers: { "cache-control": "no-store" } });
    }
    return new Response("skyphusion-monitor", { status: 200 });
  },
};
