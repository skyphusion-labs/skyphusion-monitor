// monitor#101 (c): the cert warning's delivery result was ignored after the cert-check state key
// advanced, so a failed warning was invisible for the 20h window; and an unset CF_CERT_READ_TOKEN
// was a silent no-op. Both are now visible on /health as cert.notifyFailed / cert.probeError.
// Info-only: neither flips /health ok (the surfaces themselves are still covered by uptime probes).
import { afterEach, describe, expect, it, vi } from "vitest";
import worker from "../src/index";
import type { Env } from "../src/env";

function kv() {
  const m = new Map<string, string>();
  return {
    m,
    get: async (k: string) => m.get(k) ?? null,
    put: async (k: string, v: string) => { m.set(k, v); },
    delete: async (k: string) => { m.delete(k); },
  };
}

const SOON = new Date(Date.now() + 3 * 86_400_000).toISOString(); // inside the 14 day default window

async function runCert(over: { token?: string; sendOk?: boolean } = {}): Promise<{ record: Record<string, unknown> | null; cert: Record<string, unknown> | null }> {
  const store = kv();
  const env = {
    TELEGRAM_API_BASE: "https://tg.example.invalid",
    GATUS_TELEGRAM_BOT_TOKEN: "111:AAtest",
    GATUS_TELEGRAM_CHAT_ID: "12345",
    CF_CERT_READ_TOKEN: over.token,
    RETRY_DELAY_MS: "1",
    MONITOR_STATE: store,
  } as unknown as Env;
  vi.stubGlobal("fetch", async (url: string) => {
    const u = String(url);
    if (u.endsWith("/sendMessage")) return new Response("x", { status: over.sendOk === false ? 401 : 200 });
    if (u.includes("/ssl/certificate_packs")) {
      return Response.json({ success: true, result: [{ status: "active", certificates: [{ expires_on: SOON }] }] });
    }
    if (u.includes("api.cloudflare.com/client/v4/zones")) {
      return Response.json({ success: true, result: [{ id: "z1", name: "example.invalid" }], result_info: { total_count: 1 } });
    }
    return new Response("ok", { status: 200 });
  });
  const pending: Promise<unknown>[] = [];
  await worker.scheduled({} as ScheduledEvent, env, { waitUntil: (p: Promise<unknown>) => { pending.push(p); } } as unknown as ExecutionContext);
  await Promise.all(pending);
  const raw = store.m.get("cert-check");
  const res = await worker.fetch(new Request("https://monitor.invalid/health"), env);
  const body = await res.json() as { cert: Record<string, unknown> | null };
  return { record: raw ? JSON.parse(raw) : null, cert: body.cert };
}

afterEach(() => { vi.unstubAllGlobals(); });

describe("cert probe notify result (monitor#101)", () => {
  it("control: a delivered warning is not a notify failure", async () => {
    const { record, cert } = await runCert({ token: "cert-read" });
    expect(record?.warned).toBe(1);
    expect(record?.notifyFailed).toBe(false);
    expect(cert?.notifyFailed).toBe(false);
  });

  it("records a FAILED warning delivery and shows it on /health", async () => {
    const { record, cert } = await runCert({ token: "cert-read", sendOk: false });
    expect(record?.warned).toBe(1);
    expect(record?.notifyFailed).toBe(true);
    expect(cert?.notifyFailed).toBe(true);
  });
});

describe("cert probe unset token (monitor#101)", () => {
  it("is reported as probeError on /health, not a silent no-op", async () => {
    const { record, cert } = await runCert({ token: undefined });
    expect(String(record?.error)).toContain("CF_CERT_READ_TOKEN");
    expect(cert?.probeError).toBe(true);
  });
});
