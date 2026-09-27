// The invalid-config page is deduped for 6 hours through the config-error-alerted key.
// The key must record a page that was DELIVERED: writing it before the send made a
// Telegram 5xx (or a mute transport) suppress the one page that says the monitor is
// running on no inventory, for the whole window.
import { afterEach, describe, expect, it, vi } from "vitest";
import worker from "../src/index";
import type { Env } from "../src/env";

// Drive the fail-closed path with an invalid inventory; everything else is the real engine.
vi.mock("../src/config", async (orig) => ({
  ...(await orig<typeof import("../src/config")>()),
  loadChecks: () => ({ checks: [], errors: ["test: inventory invalid"] }),
}));

function kv() {
  const m = new Map<string, string>();
  return {
    m,
    get: async (k: string) => m.get(k) ?? null,
    put: async (k: string, v: string) => { m.set(k, v); },
    delete: async (k: string) => { m.delete(k); },
  };
}

function setup(tgStatus: number) {
  const store = kv();
  const env = {
    TELEGRAM_API_BASE: "https://tg.example.invalid",
    GATUS_TELEGRAM_BOT_TOKEN: "111:AAtest",
    GATUS_TELEGRAM_CHAT_ID: "12345",
    MONITOR_STATE: store,
  } as unknown as Env;
  let sends = 0;
  vi.stubGlobal("fetch", async () => { sends++; return new Response("{}", { status: tgStatus }); });
  const run = () => worker.scheduled({} as ScheduledEvent, env, { waitUntil: () => {} } as unknown as ExecutionContext);
  return { store, run, sends: () => sends };
}

afterEach(() => {
  vi.unstubAllGlobals();
});

describe("recordConfigFailure dedupe", () => {
  it("dedupes after a DELIVERED page: one send across two runs (control)", async () => {
    const s = setup(200);
    await s.run();
    await s.run();
    expect(s.sends()).toBe(1);
    expect(s.store.m.get("config-error-alerted")).toBe("1");
  });

  it("does NOT dedupe when the send was refused: the next run retries the page", async () => {
    const s = setup(500);
    await s.run();
    expect(s.store.m.has("config-error-alerted")).toBe(false);
    await s.run();
    expect(s.sends()).toBe(2);
  });
});
