// The CI gate for the SHIPPED probe inventory (monitor#42): broken config
// cannot merge, so the runtime fail-closed path in src/index.ts is a
// last-resort tripwire, not a normal code path.
import { describe, expect, it } from "vitest";
import { loadChecks, tunables } from "../src/config";
import type { Env } from "../src/env";

describe("config/monitors.json (the shipped inventory)", () => {
  it("is valid: parseable, non-empty, unique https-only checks", () => {
    const { checks, errors } = loadChecks();
    expect(errors).toEqual([]);
    expect(checks.length).toBeGreaterThan(0);
  });

  it("covers both kinds (an inventory losing all posture checks is a config bug)", () => {
    const { checks } = loadChecks();
    expect(checks.some((c) => c.kind === "uptime")).toBe(true);
    expect(checks.some((c) => c.kind === "posture")).toBe(true);
  });

  it("posture checks that allow a 2xx carry a body-marker or header assertion", () => {
    // A posture check whose allowed set includes 200 with no content assertion
    // would pass on ANY 200 -- meaningless. Guard the shape.
    const { checks } = loadChecks();
    for (const c of checks.filter((x) => x.kind === "posture")) {
      if (c.ok.some((s) => s >= 200 && s < 300)) {
        expect(
          Boolean(c.bodyMustNotInclude?.length || (c.requireHeaders && Object.keys(c.requireHeaders).length)),
          `posture check ${c.name} allows 2xx without a content assertion`,
        ).toBe(true);
      }
    }
  });
});

describe("tunables", () => {
  const baseEnv = {} as Env;

  it("supplies safe defaults when vars are unset", () => {
    const t = tunables(baseEnv);
    expect(t.fetchTimeoutMs).toBe(12_000);
    expect(t.retryDelayMs).toBe(1_500);
    expect(t.healthStaleMs).toBe(12 * 60_000);
    expect(t.certWarnDays).toBe(14);
    expect(t.certCheckIntervalMs).toBe(20 * 3_600_000);
    expect(t.deadmanFrom).toBe("noreply@skyphusion.org");
  });

  it("honors set vars and falls back on garbage (a bad var can never break a run)", () => {
    const t = tunables({ ...baseEnv, FETCH_TIMEOUT_MS: "5000", CERT_WARN_DAYS: "banana", HEALTH_STALE_MIN: "-3" } as Env);
    expect(t.fetchTimeoutMs).toBe(5_000);
    expect(t.certWarnDays).toBe(14);
    expect(t.healthStaleMs).toBe(12 * 60_000);
  });
});
