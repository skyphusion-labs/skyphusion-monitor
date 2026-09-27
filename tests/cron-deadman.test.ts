// The cron dead-man is the INDEPENDENT observer of this Worker: HC.io pages on the
// absence of the ping. A ping that is skipped without a trace makes the observer's
// own credential the one unobserved link in the chain, so each skip path must leave
// a log line, and a padded secret (shell-to-file puts) must still ping.
import { afterEach, describe, expect, it, vi } from "vitest";
import worker from "../src/index";
import type { Env } from "../src/env";

const PING = "https://hc-ping.com/abc-123";

function kv() {
  const m = new Map<string, string>();
  return {
    get: async (k: string) => m.get(k) ?? null,
    put: async (k: string, v: string) => { m.set(k, v); },
    delete: async (k: string) => { m.delete(k); },
  };
}

function envWith(over: Record<string, string | undefined>): Env {
  return {
    TELEGRAM_API_BASE: "https://tg.example.invalid",
    GATUS_TELEGRAM_BOT_TOKEN: "111:AAtest",
    GATUS_TELEGRAM_CHAT_ID: "12345",
    RETRY_DELAY_MS: "1",
    MONITOR_STATE: kv(),
    ...over,
  } as unknown as Env;
}

async function runScheduled(env: Env): Promise<{ pinged: string[]; logs: string }> {
  const pinged: string[] = [];
  const logs: string[] = [];
  vi.stubGlobal("fetch", async (url: string) => {
    if (String(url).startsWith("https://hc-ping.com/")) pinged.push(String(url));
    return new Response("ok", { status: 200 });
  });
  vi.stubGlobal("console", { ...console, log: (...a: unknown[]) => logs.push(JSON.stringify(a)) });
  const pending: Promise<unknown>[] = [];
  const ctx = { waitUntil: (p: Promise<unknown>) => { pending.push(p); } } as unknown as ExecutionContext;
  await worker.scheduled({} as ScheduledEvent, env, ctx);
  await Promise.all(pending);
  return { pinged, logs: logs.join(" ") };
}

afterEach(() => {
  vi.unstubAllGlobals();
});

describe("scheduled(): cron dead-man ping guard", () => {
  it("pings a well-formed URL (control: the ping path can fire)", async () => {
    const r = await runScheduled(envWith({ HC_CRON_PING_URL: PING }));
    expect(r.pinged).toEqual([PING]);
  });

  it("pings when the secret carries leading whitespace, as pingDeadman already tolerates", async () => {
    const r = await runScheduled(envWith({ HC_CRON_PING_URL: `  ${PING}\n` }));
    expect(r.pinged).toEqual([PING]);
  });

  it("logs when HC_CRON_PING_URL is unset instead of skipping silently", async () => {
    const r = await runScheduled(envWith({ HC_CRON_PING_URL: undefined }));
    expect(r.pinged).toEqual([]);
    expect(r.logs).toContain("HC_CRON_PING_URL");
  });

  it("logs when HC_CRON_PING_URL is not an hc-ping.com URL, and never logs its value", async () => {
    const bad = "https://evil.example.invalid/secret-part";
    const r = await runScheduled(envWith({ HC_CRON_PING_URL: bad }));
    expect(r.pinged).toEqual([]);
    expect(r.logs).toContain("HC_CRON_PING_URL");
    expect(r.logs).not.toContain("secret-part");
  });

  it("still suppresses the ping when alerting is mute (fc#2079)", async () => {
    const r = await runScheduled(envWith({ HC_CRON_PING_URL: PING, GATUS_TELEGRAM_BOT_TOKEN: undefined }));
    expect(r.pinged).toEqual([]);
    expect(r.logs).toContain("SUPPRESSED");
  });
});
