import { describe, expect, it } from "vitest";
import {
  assessResponse,
  isValidCheck,
  statusMatches,
  uniqueCheckNames,
  validateChecks,
  type CheckConfig,
} from "../src/validate";

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
    expect(
      isValidCheck({
        ...base,
        kind: "posture",
        note: "n",
        bodyMustNotInclude: ["marker"],
        requireHeaders: { "x-content-type-options": "nosniff" },
        timeoutMs: 5000,
      }),
    ).toBe(true);
  });

  it("rejects missing HTTPS URLs", () => {
    expect(isValidCheck({ ...base, url: "http://example.com/" })).toBe(false);
  });

  it("rejects empty expected status lists", () => {
    expect(isValidCheck({ ...base, ok: [] })).toBe(false);
  });

  it("rejects non-integer or out-of-range statuses", () => {
    expect(isValidCheck({ ...base, ok: [200.5] })).toBe(false);
    expect(isValidCheck({ ...base, ok: [99] })).toBe(false);
  });

  it("rejects empty body markers and empty header expectations", () => {
    expect(isValidCheck({ ...base, bodyMustNotInclude: [""] })).toBe(false);
    expect(isValidCheck({ ...base, requireHeaders: { "x-h": "" } })).toBe(false);
  });

  it("rejects a non-positive timeout override", () => {
    expect(isValidCheck({ ...base, timeoutMs: 0 })).toBe(false);
    expect(isValidCheck({ ...base, timeoutMs: 1.5 })).toBe(false);
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

describe("validateChecks", () => {
  it("rejects non-array / empty inventories (the fail-closed trigger)", () => {
    expect(validateChecks(undefined)).toEqual(["checks is not an array"]);
    expect(validateChecks([])).toEqual(["checks is empty"]);
  });

  it("names the invalid entry and detects duplicates", () => {
    const bad = validateChecks([
      { name: "good", url: "https://a.test/", ok: [200], kind: "uptime" },
      { name: "bad", url: "http://a.test/", ok: [200], kind: "uptime" },
    ]);
    expect(bad).toEqual(["invalid check at index 1 (bad)"]);
    const dup = validateChecks([
      { name: "x", url: "https://a.test/", ok: [200], kind: "uptime" },
      { name: "x", url: "https://b.test/", ok: [200], kind: "uptime" },
    ]);
    expect(dup).toEqual(["duplicate check names"]);
  });
});

describe("assessResponse", () => {
  const check: CheckConfig = {
    name: "posture",
    url: "https://x.test/",
    ok: [302, 401, 403],
    kind: "posture",
    bodyMustNotInclude: ["secret-marker"],
    requireHeaders: undefined,
  };
  const noHeaders = () => null;

  it("passes on an allowed status with a clean body", () => {
    expect(assessResponse(check, 302, noHeaders, "")).toEqual({ ok: true });
  });

  it("fails on a disallowed status", () => {
    const a = assessResponse(check, 200, noHeaders, "");
    expect(a.ok).toBe(false);
    expect(a.reason).toContain("status 200 not in 302/401/403");
  });

  it("fails when the body leaks a marker even on an allowed status", () => {
    const a = assessResponse(check, 403, noHeaders, "... secret-marker ...");
    expect(a.ok).toBe(false);
    expect(a.reason).toContain("secret-marker");
  });

  it("fails on a missing or mismatched required header", () => {
    const c: CheckConfig = {
      name: "u",
      url: "https://x.test/",
      ok: [200],
      kind: "uptime",
      requireHeaders: { "x-content-type-options": "nosniff" },
    };
    expect(assessResponse(c, 200, () => null, "").ok).toBe(false);
    expect(assessResponse(c, 200, () => "sniff-away", "").ok).toBe(false);
    expect(assessResponse(c, 200, () => "NOSNIFF", "").ok).toBe(true); // case-insensitive
  });
});
