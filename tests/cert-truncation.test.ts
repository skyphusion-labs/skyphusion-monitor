// The cert-expiry probe lists zones with per_page=50. Without a total_count check a
// 51st zone is silently unprobed and the census reads complete. A truncated list must
// be recorded as a probe error (visible on /health as probeError), never as clean.
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

async function runWithZoneTotal(total: number): Promise<{ cert: { error?: string; zones?: number } }> {
  const store = kv();
  const env = {
    TELEGRAM_API_BASE: "https://tg.example.invalid",
    GATUS_TELEGRAM_BOT_TOKEN: "111:AAtest",
    GATUS_TELEGRAM_CHAT_ID: "12345",
    CF_CERT_READ_TOKEN: "cert-read",
    RETRY_DELAY_MS: "1",
    MONITOR_STATE: store,
  } as unknown as Env;
  vi.stubGlobal("fetch", async (url: string) => {
    const u = String(url);
    if (u.includes("/ssl/certificate_packs")) {
      return Response.json({ success: true, result: [] });
    }
    if (u.includes("api.cloudflare.com/client/v4/zones")) {
      return Response.json({ success: true, result: [{ id: "z1", name: "example.invalid" }], result_info: { total_count: total } });
    }
    return new Response("ok", { status: 200 });
  });
  const pending: Promise<unknown>[] = [];
  await worker.scheduled({} as ScheduledEvent, env, { waitUntil: (p: Promise<unknown>) => { pending.push(p); } } as unknown as ExecutionContext);
  await Promise.all(pending);
  return { cert: JSON.parse(store.m.get("cert-check")!) };
}

afterEach(() => {
  vi.unstubAllGlobals();
});

describe("maybeCheckCerts zone census", () => {
  it("records a complete census cleanly (control)", async () => {
    const { cert } = await runWithZoneTotal(1);
    expect(cert.error).toBeUndefined();
    expect(cert.zones).toBe(1);
  });

  it("records a probe error when total_count exceeds the zones returned", async () => {
    const { cert } = await runWithZoneTotal(51);
    expect(cert.error).toContain("truncated");
  });
});
