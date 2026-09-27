// Telegram rejects sendMessage text over 4096 characters. The widest outage builds
// the longest alert body, so an uncapped body makes the page that matters most the
// one that fails, and that failure then reads as a mute channel.
import { afterEach, describe, expect, it, vi } from "vitest";
import { notify } from "../src/index";
import type { Env } from "../src/env";

const env = {
  TELEGRAM_API_BASE: "https://tg.example.invalid",
  GATUS_TELEGRAM_BOT_TOKEN: "111:AAtest",
  GATUS_TELEGRAM_CHAT_ID: "12345",
} as unknown as Env;

afterEach(() => {
  vi.unstubAllGlobals();
});

async function sentText(body: string): Promise<string> {
  let text = "";
  vi.stubGlobal("fetch", async (_u: string, init: RequestInit) => {
    text = (JSON.parse(String(init.body)) as { text: string }).text;
    return new Response("{}", { status: 200 });
  });
  await notify(env, "title", body, true, "rotating_light");
  return text;
}

describe("notify(): Telegram 4096 character limit", () => {
  it("sends a short body unchanged (control: the cap does not touch small alerts)", async () => {
    const t = await sentText("one line");
    expect(t).toContain("one line");
    expect(t).not.toContain("truncated");
  });

  it("caps an oversized body at 4096 characters and says it was truncated", async () => {
    const t = await sentText("x".repeat(6000));
    expect(t.length).toBeLessThanOrEqual(4096);
    expect(t).toContain("truncated");
    expect(t.startsWith("[URGENT] title")).toBe(true);
    expect(t.endsWith("(rotating_light)")).toBe(true);
  });

  it("does not split a surrogate pair at the cut", async () => {
    const t = await sentText("\u{1F6A8}".repeat(3000));
    expect(t.length).toBeLessThanOrEqual(4096);
    expect(t).not.toMatch(/[\uD800-\uDBFF](?![\uDC00-\uDFFF])/);
  });
});
