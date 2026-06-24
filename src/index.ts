// skyphusion-monitor: external security-posture + uptime checks from the CF edge.
// Runs on a cron; alerts to ntfy ONLY when a check fails its expectation (quiet when healthy).
// Two check kinds:
//   uptime  -- the public surface should be reachable (2xx/3xx).
//   posture -- a SECURITY expectation that must hold; a change is a regression:
//              * Access-gated endpoints must answer 401/403 to an anonymous edge fetch
//                (a 200 means the Access gate dropped -- data-plane exposure).
//              * *.workers.dev hostnames must answer 404 (workers_dev must stay false --
//                this is the F1 regression tripwire).
import type { Env } from "./env";

type Kind = "uptime" | "posture";
interface Check { name: string; url: string; ok: number[]; kind: Kind; note?: string }

const CHECKS: Check[] = [
  // --- uptime: public surfaces should serve ---
  { name: "intro-apex",   url: "https://skyphusion.org/",          ok: [200, 301, 302, 308], kind: "uptime" },
  { name: "intro-www",    url: "https://www.skyphusion.org/",      ok: [200, 301, 302, 308], kind: "uptime" },
  { name: "blog",         url: "https://skyphusion.net/",          ok: [200, 301, 302, 308], kind: "uptime" },
  { name: "playground",   url: "https://play.skyphusion.org/",     ok: [200, 302],           kind: "uptime" },
  { name: "status-gatus", url: "https://status.skyphusion.org/",   ok: [200],                kind: "uptime" },
  { name: "authentik",    url: "https://auth.skyphusion.org/",     ok: [200, 302],           kind: "uptime" },
  { name: "ntfy",         url: "https://ntfy.skyphusion.org/",     ok: [200],                kind: "uptime" },

  // --- security posture: these MUST hold; a change is a regression ---
  { name: "vivijure-access-gated", url: "https://vivijure.skyphusion.org/api/modules",
    ok: [401, 403], kind: "posture", note: "anon must be Access-blocked; 200 = exposure regression" },
  { name: "vivijure-workersdev-closed", url: "https://vivijure-studio.skyphusion.workers.dev/api/modules",
    ok: [404, 530, 1033], kind: "posture", note: "workers_dev must stay false; 200/serving = F1 regression" },
];

interface Result { name: string; kind: Kind; url: string; status: number | null; expected: number[]; ok: boolean; note?: string; err?: string }

async function runCheck(c: Check): Promise<Result> {
  const ctrl = new AbortController();
  const t = setTimeout(() => ctrl.abort(), 12_000);
  try {
    const res = await fetch(c.url, { method: "GET", redirect: "manual", signal: ctrl.signal,
      headers: { "user-agent": "skyphusion-monitor/1 (+external posture probe)" } });
    const ok = c.ok.includes(res.status);
    return { name: c.name, kind: c.kind, url: c.url, status: res.status, expected: c.ok, ok, note: c.note };
  } catch (e) {
    return { name: c.name, kind: c.kind, url: c.url, status: null, expected: c.ok, ok: false, note: c.note, err: String(e) };
  } finally {
    clearTimeout(t);
  }
}

async function runAll(): Promise<Result[]> {
  return Promise.all(CHECKS.map(runCheck));
}

async function alert(env: Env, fails: Result[]): Promise<void> {
  if (!env.NTFY_TOKEN || !env.NTFY_URL || !env.MONITOR_TOPIC) return;
  const posture = fails.filter(f => f.kind === "posture");
  const title = posture.length
    ? `SECURITY: ${posture.length} posture regression(s) + ${fails.length - posture.length} uptime`
    : `skyphusion: ${fails.length} surface(s) down`;
  const lines = fails.map(f =>
    `${f.kind === "posture" ? "[SECURITY] " : ""}${f.name}: got ${f.status ?? f.err} (want ${f.expected.join("/")})` +
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
  async scheduled(_event: ScheduledEvent, env: Env, ctx: ExecutionContext): Promise<void> {
    const results = await runAll();
    const fails = results.filter(r => !r.ok);
    if (fails.length) ctx.waitUntil(alert(env, fails));
  },

  async fetch(req: Request, env: Env): Promise<Response> {
    const url = new URL(req.url);
    if (url.pathname === "/health") {
      return new Response(JSON.stringify({ service: "skyphusion-monitor", checks: CHECKS.length, topic: env.MONITOR_TOPIC }), { headers: { "content-type": "application/json" } });
    }
    if (url.pathname === "/run") {
      // gated manual run (returns the result set; alerts on failures too)
      if (!env.RUN_KEY || url.searchParams.get("key") !== env.RUN_KEY) return new Response("forbidden", { status: 403 });
      const results = await runAll();
      const fails = results.filter(r => !r.ok);
      if (fails.length) await alert(env, fails);
      return new Response(JSON.stringify({ failures: fails.length, results }, null, 2), { headers: { "content-type": "application/json" } });
    }
    return new Response("skyphusion-monitor", { status: 200 });
  },
};
