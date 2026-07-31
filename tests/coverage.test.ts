// fc#1194 A1 / fc#1180 F2 -- the workers.dev coverage assessor.
//
// DEFINITION OF DONE for this repo: a check does not count as fixed until it has
// been made to FAIL on purpose. Every rule below has a test that watches it
// report the BAD state, and the healthy case carries a control proving the pass
// is not vacuous (drop one allowance from the same census and it fails).
//
// What these tests deliberately do NOT prove: that the live account matches the
// census used here. Only the deployed sweep against the real API proves that.
// These prove the DECISION PATH, which is the half a stub can prove.
import { describe, expect, it } from "vitest";
import {
  assessWorkersDevCoverage,
  coverageSignature,
  summarizeCoverage,
  validateWorkersDevPolicy,
  type SubdomainState,
  type WorkersDevPolicy,
} from "../src/coverage";
import { loadChecks, loadWorkersDevPolicy } from "../src/config";

/** The live census shape at 2026-08-01: 56 Workers, 3 with workers.dev + previews on. */
const LIVE_ENABLED = ["sidvicious-search", "slate-logs", "slate-search"];
function liveCensus(): SubdomainState[] {
  const off: SubdomainState[] = Array.from({ length: 53 }, (_, i) => ({
    script: `worker-off-${String(i).padStart(2, "0")}`,
    enabled: false,
    previewsEnabled: false,
  }));
  const on: SubdomainState[] = LIVE_ENABLED.map((script) => ({ script, enabled: true, previewsEnabled: true }));
  return [...off, ...on];
}
function livePolicy(): WorkersDevPolicy {
  return { allowed: LIVE_ENABLED.map((script) => ({ script, reason: `test reason ${script}`, coverage: "monitor#44" })) };
}

describe("assessWorkersDevCoverage -- healthy case + its control", () => {
  it("PASSES on the live census when every enabled Worker is declared", () => {
    expect(assessWorkersDevCoverage(liveCensus(), livePolicy())).toEqual([]);
  });

  it("CONTROL: the same census FAILS when one allowance is dropped (the pass is not vacuous)", () => {
    const policy = { allowed: livePolicy().allowed.filter((a) => a.script !== "slate-search") };
    const findings = assessWorkersDevCoverage(liveCensus(), policy);
    // slate-search loses its allowance -> both its workers.dev and its preview URLs are undeclared.
    expect(findings.map((f) => f.code).sort()).toEqual(["preview-urls-undeclared", "workers-dev-undeclared"]);
    expect(new Set(findings.map((f) => f.script))).toEqual(new Set(["slate-search"]));
  });
});

describe("assessWorkersDevCoverage -- made to fail on purpose", () => {
  it("FAILS on a Worker that appears tomorrow with workers.dev on and no allowance", () => {
    // The whole point of deriving the list from the API: nobody has to remember this Worker.
    const census = [...liveCensus(), { script: "brand-new-worker", enabled: true, previewsEnabled: false }];
    const findings = assessWorkersDevCoverage(census, livePolicy());
    expect(findings).toHaveLength(1);
    expect(findings[0].code).toBe("workers-dev-undeclared");
    expect(findings[0].script).toBe("brand-new-worker");
  });

  it("FAILS on preview URLs enabled without an allowance (the second bypass hostname)", () => {
    const census = [...liveCensus(), { script: "preview-only", enabled: false, previewsEnabled: true }];
    const findings = assessWorkersDevCoverage(census, livePolicy());
    expect(findings).toHaveLength(1);
    expect(findings[0].code).toBe("preview-urls-undeclared");
  });

  it("FAILS on UNKNOWN preview state rather than reading it as off", () => {
    const census = [...liveCensus(), { script: "unknowable", enabled: false, previewsEnabled: null }];
    const findings = assessWorkersDevCoverage(census, livePolicy());
    expect(findings).toHaveLength(1);
    expect(findings[0].code).toBe("preview-state-unknown");
  });

  it("FAILS on a STALE allowance, so the list cannot rot into a permanent silent pass", () => {
    // slate-logs got turned off; the allowance outlived it.
    const census = liveCensus().map((s) => (s.script === "slate-logs" ? { ...s, enabled: false, previewsEnabled: false } : s));
    const findings = assessWorkersDevCoverage(census, livePolicy());
    expect(findings).toHaveLength(1);
    expect(findings[0].code).toBe("allowance-stale");
    expect(findings[0].script).toBe("slate-logs");
  });

  it("FAILS on an allowance naming a Worker that does not exist", () => {
    const policy = { allowed: [...livePolicy().allowed, { script: "deleted-worker", reason: "r", coverage: "c" }] };
    const findings = assessWorkersDevCoverage(liveCensus(), policy);
    expect(findings).toHaveLength(1);
    expect(findings[0].code).toBe("allowance-without-script");
  });

  it("FAILS on a zero-length enumeration (empty success != empty account, fc#1180 F5)", () => {
    const findings = assessWorkersDevCoverage([], livePolicy());
    expect(findings).toHaveLength(1);
    expect(findings[0].code).toBe("enumeration-empty");
  });

  it("reports EVERY undeclared Worker, not just the first", () => {
    const census = [
      ...liveCensus(),
      { script: "new-a", enabled: true, previewsEnabled: false },
      { script: "new-b", enabled: true, previewsEnabled: false },
    ];
    const findings = assessWorkersDevCoverage(census, livePolicy());
    expect(findings.map((f) => f.script)).toEqual(["new-a", "new-b"]);
  });

  it("orders findings deterministically so the alert signature is stable", () => {
    const census = [
      ...liveCensus(),
      { script: "zzz", enabled: true, previewsEnabled: false },
      { script: "aaa", enabled: true, previewsEnabled: false },
    ];
    const a = coverageSignature(assessWorkersDevCoverage(census, livePolicy()));
    const b = coverageSignature(assessWorkersDevCoverage([...census].reverse(), livePolicy()));
    expect(a).toBe(b);
    expect(a).toBe("aaa:workers-dev-undeclared,zzz:workers-dev-undeclared");
  });

  it("summarizes findings without swallowing the count", () => {
    const census = liveCensus().concat(
      Array.from({ length: 10 }, (_, i) => ({ script: `extra-${i}`, enabled: true, previewsEnabled: false })),
    );
    const s = summarizeCoverage(assessWorkersDevCoverage(census, livePolicy()), census.length);
    expect(s).toContain("10 finding(s)");
    expect(s).toContain("+2 more");
  });
});

describe("validateWorkersDevPolicy -- an unusable policy must fail closed", () => {
  it("accepts the shipped policy", () => {
    const { policy, errors } = loadWorkersDevPolicy();
    expect(errors).toEqual([]);
    expect(policy.allowed.length).toBeGreaterThan(0);
  });

  it("requires a reason AND a coverage pointer on every allowance", () => {
    expect(validateWorkersDevPolicy({ allowed: [{ script: "x", coverage: "c" }] })).toEqual([
      "workersDev.allowed[0] (x): missing reason",
    ]);
    expect(validateWorkersDevPolicy({ allowed: [{ script: "x", reason: "r" }] })).toEqual([
      "workersDev.allowed[0] (x): missing coverage pointer",
    ]);
    expect(validateWorkersDevPolicy({ allowed: [{ script: "x", reason: "  ", coverage: "  " }] })).toHaveLength(2);
  });

  it("rejects duplicates, bad names, and non-array shapes", () => {
    expect(validateWorkersDevPolicy({ allowed: [
      { script: "dup", reason: "r", coverage: "c" },
      { script: "dup", reason: "r", coverage: "c" },
    ] })).toEqual(["workersDev.allowed[1] (dup): duplicate script"]);
    expect(validateWorkersDevPolicy({ allowed: [{ script: "Bad Name", reason: "r", coverage: "c" }] }))
      .toEqual(["workersDev.allowed[0] (Bad Name): invalid script name"]);
    expect(validateWorkersDevPolicy({ allowed: "nope" })).toEqual(["workersDev.allowed is not an array"]);
    expect(validateWorkersDevPolicy([])).toEqual(["workersDev is not an object"]);
    expect(validateWorkersDevPolicy(null)).toEqual(["workersDev is not an object"]);
  });

  it("accepts an EMPTY allowance list (a healthy account declares nothing)", () => {
    expect(validateWorkersDevPolicy({ allowed: [] })).toEqual([]);
  });
});

describe("the shipped inventory cannot carry an unfalsifiable workers.dev probe", () => {
  // Regression guard for the defect this replaces. Cloudflare answers 404
  // `error code: 1042` for every sibling *.workers.dev subrequest, enabled or
  // disabled, so ANY probe at such a hostname passes forever. Re-adding one is
  // the mistake to catch at review time, not in production.
  it("no check in config/monitors.json probes a *.workers.dev hostname", () => {
    const { checks } = loadChecks();
    for (const c of checks) {
      const host = new URL(c.url).hostname;
      expect(host.endsWith(".workers.dev"), `${c.name} probes ${host}; this Worker cannot see its real status (CF 1042)`).toBe(false);
    }
  });
});
