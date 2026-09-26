// The alert channel is the one thing in this Worker that cannot be allowed to
// fail quietly: every other defect surfaces as an alert, and a defect in
// alerting surfaces as SILENCE. fc#2079 found this Worker in exactly that state
// -- 3 checks failing, marked sick, and every page going to a host that answered
// 530 -- for days, while /health, the cron and the HC dead-man all stayed green.
//
// So these tests are not about happy-path formatting. Each one names the reading
// that would prove the guard wrong and then shows the instrument can produce it:
// the transport CAN return null, notify() CAN return false on a real refusal, and
// a mute channel DOES flip isSickFromLastRun() with zero check failures.
import { afterEach, describe, expect, it, vi } from "vitest";
import { alertTransport, isSickFromLastRun, notify } from "../src/index";
import type { Env } from "../src/env";

// TELEGRAM_API_BASE is a var precisely so this file needs neither real secret.
const base = {
  TELEGRAM_API_BASE: "https://tg.example.invalid",
  GATUS_TELEGRAM_BOT_TOKEN: "111:AAtest",
  GATUS_TELEGRAM_CHAT_ID: "12345",
} as unknown as Env;

afterEach(() => {
  vi.unstubAllGlobals();
});

describe("alertTransport (the primary alert channel)", () => {
  it("resolves the Telegram sendMessage endpoint from the two secrets", () => {
    const t = alertTransport(base);
    expect(t).not.toBeNull();
    expect(t!.url).toBe("https://tg.example.invalid/bot111:AAtest/sendMessage");
    expect(t!.chatId).toBe("12345");
  });

  it("defaults to api.telegram.org when the base var is unset", () => {
    const t = alertTransport({ ...base, TELEGRAM_API_BASE: undefined } as unknown as Env);
    expect(t!.url).toBe("https://api.telegram.org/bot111:AAtest/sendMessage");
  });

  it("defaults to api.telegram.org when the base var is blank, not to an empty host", () => {
    const t = alertTransport({ ...base, TELEGRAM_API_BASE: "   " } as unknown as Env);
    expect(t!.url).toBe("https://api.telegram.org/bot111:AAtest/sendMessage");
  });

  it("trims a trailing slash on the base so the bot path cannot double up", () => {
    const t = alertTransport({ ...base, TELEGRAM_API_BASE: "https://tg.example.invalid/" } as unknown as Env);
    expect(t!.url).toBe("https://tg.example.invalid/bot111:AAtest/sendMessage");
  });

  // The negative half. These prove the function CAN answer null, so the positive
  // assertions above are not a function that always says yes.
  it("returns null with no bot token (nothing to post as)", () => {
    expect(alertTransport({ ...base, GATUS_TELEGRAM_BOT_TOKEN: undefined } as unknown as Env)).toBeNull();
  });

  it("returns null with no chat id (nobody to post to)", () => {
    expect(alertTransport({ ...base, GATUS_TELEGRAM_CHAT_ID: undefined } as unknown as Env)).toBeNull();
  });

  it("returns null on whitespace-only secrets (a `wrangler secret put` with a stray newline)", () => {
    expect(alertTransport({ ...base, GATUS_TELEGRAM_BOT_TOKEN: " ", GATUS_TELEGRAM_CHAT_ID: " " } as unknown as Env)).toBeNull();
  });
});

describe("notify (delivery is a VERDICT, not a side effect)", () => {
  it("returns true and posts chat_id plus text when the transport accepts", async () => {
    const seen: { url?: string; body?: unknown } = {};
    vi.stubGlobal("fetch", async (url: string, init: RequestInit) => {
      seen.url = url;
      seen.body = JSON.parse(String(init.body));
      return new Response("{\"ok\":true}", { status: 200 });
    });
    await expect(notify(base, "title", "body", false, "warning")).resolves.toBe(true);
    expect(seen.url).toBe("https://tg.example.invalid/bot111:AAtest/sendMessage");
    expect(seen.body).toMatchObject({ chat_id: "12345" });
    expect(String((seen.body as { text: string }).text)).toContain("title");
  });

  // THE REGRESSION THAT CAUSED fc#2079. The old notify() awaited fetch and threw
  // the Response away, so a rotated token (401) or a bot blocked by its recipient
  // (403) was indistinguishable from a delivered page. This is the reading that
  // would have proven the old guard wrong, and it must stay producible.
  it("returns FALSE on a 401 -- a rotated token must not read as a delivered page", async () => {
    vi.stubGlobal("fetch", async () => new Response("unauthorized", { status: 401 }));
    await expect(notify(base, "title", "body", true, "rotating_light")).resolves.toBe(false);
  });

  it("returns FALSE on a 403 -- a bot blocked by its recipient is still mute", async () => {
    vi.stubGlobal("fetch", async () => new Response("forbidden", { status: 403 }));
    await expect(notify(base, "title", "body", true, "rotating_light")).resolves.toBe(false);
  });

  it("returns FALSE when the fetch THROWS, instead of rejecting the whole run", async () => {
    vi.stubGlobal("fetch", async () => { throw new Error("network"); });
    await expect(notify(base, "title", "body", false, "warning")).resolves.toBe(false);
  });

  it("returns FALSE without calling fetch at all when the transport is unconfigured", async () => {
    const calls: number[] = [];
    vi.stubGlobal("fetch", async () => { calls.push(1); return new Response("", { status: 200 }); });
    await expect(notify({} as unknown as Env, "t", "b", false, "warning")).resolves.toBe(false);
    expect(calls).toHaveLength(0);
  });

  // The bot token is a PATH SEGMENT of the request url, so any diagnostic that
  // echoes the url leaks a live credential into the Worker log. Assert the token
  // never reaches console.log on the failure path, where the temptation is worst.
  it("never writes the bot token to the log on a refusal", async () => {
    vi.stubGlobal("fetch", async () => new Response("unauthorized", { status: 401 }));
    const lines: string[] = [];
    vi.stubGlobal("console", { ...console, log: (...a: unknown[]) => lines.push(JSON.stringify(a)) });
    await notify(base, "title", "body", true, "rotating_light");
    expect(lines.join(" ")).not.toContain("111:AAtest");
    expect(lines.join(" ")).toContain("401");
  });
});

describe("a mute channel is a SICK monitor (fc#2079)", () => {
  it("flips sick with ZERO check failures -- the mute is the fault, not a symptom", () => {
    expect(isSickFromLastRun({ failures: 0, posture: 0, alertingMute: true })).toBe(true);
  });

  // The control: same record, mute cleared, must go back to healthy. A guard that
  // cannot return false is not a guard.
  it("is healthy on the same record with the mute cleared", () => {
    expect(isSickFromLastRun({ failures: 0, posture: 0, alertingMute: false })).toBe(false);
  });

  it("stays healthy when alertingMute is absent entirely (old records predate the field)", () => {
    expect(isSickFromLastRun({ failures: 0, posture: 0 })).toBe(false);
  });

  it("still flips on ordinary check failures, mute or not", () => {
    expect(isSickFromLastRun({ failures: 2, posture: 0, alertingMute: false })).toBe(true);
  });
});
