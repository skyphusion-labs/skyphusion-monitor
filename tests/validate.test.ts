import { describe, expect, it } from "vitest";
import { isValidCheck, statusMatches, uniqueCheckNames, type CheckConfig } from "../src/validate";

describe("statusMatches", () => {
  it("accepts statuses in the allowed set", () => {
    expect(statusMatches(200, [200, 302])).toBe(true);
    expect(statusMatches(404, [404, 530])).toBe(true);
  });

  it("rejects statuses outside the allowed set", () => {
    expect(statusMatches(500, [200, 302])).toBe(false);
  });
});

describe("isValidCheck", () => {
  const base: CheckConfig = {
    name: "intro-apex",
    url: "https://skyphusion.org/",
    ok: [200, 302],
    kind: "uptime",
  };

  it("accepts well-formed probe definitions", () => {
    expect(isValidCheck(base)).toBe(true);
  });

  it("rejects missing HTTPS URLs", () => {
    expect(isValidCheck({ ...base, url: "http://example.com/" })).toBe(false);
  });

  it("rejects empty expected status lists", () => {
    expect(isValidCheck({ ...base, ok: [] })).toBe(false);
  });
});

describe("uniqueCheckNames", () => {
  it("detects duplicate probe names", () => {
    const checks: CheckConfig[] = [
      { name: "a", url: "https://a.test/", ok: [200], kind: "uptime" },
      { name: "a", url: "https://b.test/", ok: [200], kind: "uptime" },
    ];
    expect(uniqueCheckNames(checks)).toBe(false);
  });
});
