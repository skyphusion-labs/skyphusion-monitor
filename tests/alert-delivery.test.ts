// monitor#100: alertingMute must reflect the LAST alert-delivery outcome, not only "was a send
// attempted on THIS run". Before, a standing non-alertable failure (workers.dev coverage pages hourly,
// not every 5 minutes) meant no send was attempted on 11 runs in 12, so mute read false, the
// dead-man ping went out, and a dead Telegram channel looked healthy to both observers.
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import worker from "../src/index";
import type { Env } from "../src/env";

// No probe inventory: the only failures are the COVER/SCHED verdicts, which (unset credentials)
// FAIL on their first sweep and are then cached, non-alertable, until the sweep interval passes.
vi.mock("../src/config", async (orig) => ({
  ...(await orig<typeof import("../src/config")>()),
  loadChecks: () => ({ checks: [], errors: [] }),
}));

const PING = "https://hc-ping.com/abc-123";
const TG = "https://tg.example.invalid";

function kv() {
  const m = new Map<string, string>();
  return {
    m,
    get: async (k: string) => m.get(k) ?? null,
    put: async (k: string, v: string) => { m.set(k, v); },
    delete: async (k: string) => { m.delete(k); },
  };
}

interface Net { sendOk: boolean; getMeOk: boolean; calls: string[]; pinged: string[] }
let net: Net;
let store: ReturnType<typeof kv>;

function env(over: Record<string, string | undefined> = {}): Env {
  return {
    TELEGRAM_API_BASE: TG,
    GATUS_TELEGRAM_BOT_TOKEN: "111:AAtest",
    GATUS_TELEGRAM_CHAT_ID: "12345",
    HC_CRON_PING_URL: PING,
    RETRY_DELAY_MS: "1",
    MONITOR_STATE: store,
    ...over,
  } as unknown as Env;
}

async function run(e: Env): Promise<{ mute: boolean; logs: string }> {
  const logs: string[] = [];
  vi.stubGlobal("fetch", async (url: string) => {
    const u = String(url);
    if (u.startsWith("https://hc-ping.com/")) { net.pinged.push(u); return new Response("ok"); }
    if (u.endsWith("/sendMessage")) { net.calls.push("send"); return new Response("x", { status: net.sendOk ? 200 : 401 }); }
    if (u.endsWith("/getMe")) { net.calls.push("getMe"); return new Response("x", { status: net.getMeOk ? 200 : 401 }); }
    return new Response("ok", { status: 200 });
  });
  vi.stubGlobal("console", { ...console, log: (...a: unknown[]) => logs.push(JSON.stringify(a)) });
  const pending: Promise<unknown>[] = [];
  const ctx = { waitUntil: (p: Promise<unknown>) => { pending.push(p); } } as unknown as ExecutionContext;
  await worker.scheduled({} as ScheduledEvent, e, ctx);
  await Promise.all(pending);
  const last = JSON.parse(store.m.get("last-run")!) as { alertingMute: boolean };
  return { mute: last.alertingMute, logs: logs.join(" ") };
}

beforeEach(() => { store = kv(); net = { sendOk: true, getMeOk: true, calls: [], pinged: [] }; });
afterEach(() => { vi.unstubAllGlobals(); });

describe("scheduled(): alert delivery outcome persists (monitor#100)", () => {
  it("control: a healthy channel is not mute", async () => {
    const r = await run(env());
    expect(r.mute).toBe(false);
    expect(net.pinged).toEqual([PING]);
  });

  it("a failed send keeps mute TRUE on the following runs that attempt no send, and withholds the ping", async () => {
    net.sendOk = false;
    const first = await run(env());
    expect(first.mute).toBe(true);
    expect(net.calls.filter((c) => c === "send")).toHaveLength(1);

    net.pinged.length = 0;
    const second = await run(env()); // coverage + schedule verdicts cached: no alertable failure, no send
    expect(net.calls.filter((c) => c === "send")).toHaveLength(1);
    expect(second.mute).toBe(true);
    expect(net.pinged).toEqual([]);
    expect(second.logs).toContain("SUPPRESSED");
  });

  it("a later successful send clears the mute", async () => {
    net.sendOk = false;
    await run(env());
    net.sendOk = true;
    store.m.delete("workersdev-coverage"); // force a re-sweep: alertable, so a send is attempted
    const r = await run(env());
    expect(net.calls.filter((c) => c === "send")).toHaveLength(2);
    expect(r.mute).toBe(false);
  });

  it("a failure recorded against an OLD credential does not outlive a rotated secret", async () => {
    net.sendOk = false;
    await run(env());
    const r = await run(env({ GATUS_TELEGRAM_BOT_TOKEN: "222:BBrotated" }));
    expect(r.mute).toBe(false);
  });
});

describe("scheduled(): daily getMe probe (monitor#100)", () => {
  it("a revoked token is found on a QUIET run, with no alert attempted", async () => {
    await run(env()); // first run pages (coverage sweep) and primes the cached verdicts
    net.calls.length = 0;
    net.getMeOk = false;
    store.m.set("alert-probe", JSON.stringify({ ts: 0 }));
    const r = await run(env());
    expect(net.calls).toEqual(["getMe"]); // no send: nothing alertable
    expect(r.mute).toBe(true);
  });

  it("probes at most once per interval", async () => {
    await run(env());
    await run(env());
    expect(net.calls.filter((c) => c === "getMe")).toHaveLength(1);
  });

  it("a passing probe clears a probe-found failure once the interval has passed", async () => {
    net.getMeOk = false;
    await run(env());
    net.getMeOk = true;
    store.m.set("alert-probe", JSON.stringify({ ts: 0 }));
    const r = await run(env());
    expect(r.mute).toBe(false);
  });

  it("a passing probe does NOT clear a failed SEND (getMe cannot see a blocked or wrong chat)", async () => {
    net.sendOk = false;
    await run(env());
    store.m.set("alert-probe", JSON.stringify({ ts: 0 }));
    const r = await run(env()); // getMe passes, the last real send failed
    expect(net.calls).toContain("getMe");
    expect(r.mute).toBe(true);
  });

  it("never logs the token", async () => {
    net.getMeOk = false;
    net.sendOk = false;
    const r = await run(env());
    expect(r.logs).not.toContain("AAtest");
  });
});
