// SCHED.ci -- CI schedule liveness (src/schedule.ts, sweep in src/index.ts).
//
// Each rule is driven to its FAIL on purpose, with a healthy control in the same file so a check
// that always failed could not pass here. The counts in "measured days" are the real totals the
// GitHub API returned for the watched repository (2026-11-11 reading), so the verdict is tested
// against the shape that went unnoticed for seventeen days, not against an invented one.
//
// What these tests do NOT prove: that the deployed Worker reads the live API correctly. Only the
// deployed sweep proves that; these prove the decision path and the no-name rule.
import { afterEach, describe, expect, it, vi } from "vitest";
import { assessSchedule, parseRepo, type ScheduleCounts } from "../src/schedule";
import { scheduleResult, scrubRepo, sweepSchedule } from "../src/index";
import { tunables } from "../src/config";
import type { Env } from "../src/env";

const c = (startupFailures: number, scheduledTotal: number, scheduledStartupFailures: number, sample = 0): ScheduleCounts =>
  ({ startupFailures, scheduledTotal, scheduledStartupFailures, sampleStartupFailuresInWindow: sample });

describe("assessSchedule on measured days", () => {
  it("2026-11-09 (16 scheduled, 0 failed to start) is OK -- the control", () => {
    expect(assessSchedule(c(0, 16, 0), 24)).toMatchObject({ ok: true, sig: "ok" });
  });
  it("2026-11-05 (12 of 12 scheduled failed to start) FAILS", () => {
    expect(assessSchedule(c(12, 12, 12, 12), 24)).toMatchObject({ ok: false, sig: "start-failures" });
  });
  it("2026-11-10 (3 of 12 failed to start, 9 ran) FAILS: a partial block is still a block", () => {
    expect(assessSchedule(c(3, 12, 3, 3), 24)).toMatchObject({ ok: false, sig: "start-failures" });
  });
});

describe("assessSchedule failure shapes", () => {
  it("no scheduled run at all in the window FAILS", () => {
    expect(assessSchedule(c(0, 0, 0), 24)).toMatchObject({ ok: false, sig: "no-scheduled-run" });
  });
  it("a filter reading 0 while the unfiltered sample shows startup failures is UNMEASURED", () => {
    // GitHub answers total_count 0 for a status value it does not understand (measured).
    expect(assessSchedule(c(0, 12, 0, 4), 24)).toMatchObject({ ok: false, sig: "filter-disagrees" });
  });
  it("counts that do not add up are UNMEASURED", () => {
    expect(assessSchedule(c(1, 2, 3), 24).sig).toBe("bad-counts");
    expect(assessSchedule(c(-1, 2, 0), 24).sig).toBe("bad-counts");
    expect(assessSchedule({ ...c(0, 2, 0), startupFailures: 0.5 }, 24).sig).toBe("bad-counts");
    expect(assessSchedule(c(0, 2, 1), 24).sig).toBe("bad-counts"); // scheduled failures > all failures
  });
});

describe("parseRepo", () => {
  it("accepts owner/repo and refuses anything else", () => {
    expect(parseRepo(" acme-labs/some.repo_1 ")).toBe("acme-labs/some.repo_1");
    for (const bad of [undefined, "", "acme", "acme/", "/repo", "a/b/c", "acme/re po", "https://github.com/a/b"]) {
      expect(parseRepo(bad), String(bad)).toBeNull();
    }
  });
});

describe("the watched repository is never named", () => {
  const REPO = "acme-labs/secret-infra";
  const env = { GH_ACTIONS_READ_TOKEN: "t", GH_SCHEDULE_REPO: REPO } as unknown as Env;
  afterEach(() => vi.unstubAllGlobals());

  function stubRuns(byQuery: (url: string) => Response) {
    vi.stubGlobal("fetch", vi.fn(async (u: string) => byQuery(String(u))));
  }
  const json = (o: unknown, status = 200) => new Response(JSON.stringify(o), { status });

  it("an outage day reads FAIL and its summary carries no part of the repository", async () => {
    stubRuns((u) => u.includes("per_page=100")
      ? json({ workflow_runs: Array.from({ length: 5 }, () => ({ conclusion: "startup_failure", created_at: new Date().toISOString() })) })
      : json({ total_count: u.includes("event=schedule") ? 12 : 12 }));
    const st = await sweepSchedule("t", REPO, tunables(env), Date.now());
    expect(st.ok).toBe(false);
    expect(st.sig).toBe("start-failures");
    for (const part of [REPO, "acme-labs", "secret-infra"]) expect(st.summary).not.toContain(part);
  });

  it("a healthy day reads OK (control for the stub)", async () => {
    stubRuns((u) => u.includes("per_page=100")
      ? json({ workflow_runs: [{ conclusion: "success", created_at: new Date().toISOString() }] })
      : json({ total_count: u.includes("event=schedule") && !u.includes("status=") ? 16 : 0 }));
    const st = await sweepSchedule("t", REPO, tunables(env), Date.now());
    expect(st).toMatchObject({ ok: true, sig: "ok" });
  });

  it("an HTTP refusal throws with the status only", async () => {
    stubRuns(() => json({ message: `Not Found for ${REPO}` }, 404));
    await expect(sweepSchedule("t", REPO, tunables(env), Date.now())).rejects.toThrow(/^Error: GitHub API HTTP 404$|GitHub API HTTP 404/);
    try { await sweepSchedule("t", REPO, tunables(env), Date.now()); } catch (e) {
      expect(String(e)).not.toContain("secret-infra");
    }
  });

  it("scrubRepo removes the repository, the owner and the name", () => {
    const m = scrubRepo(`fetch https://api.github.com/repos/${REPO}/actions/runs failed (acme-labs)`, REPO);
    for (const part of [REPO, "acme-labs", "secret-infra"]) expect(m).not.toContain(part);
  });
});

describe("scheduleResult", () => {
  const t = tunables({} as Env);
  it("no verdict yet is a FAIL, not a pass", () => {
    expect(scheduleResult(null, t, Date.now()).ok).toBe(false);
  });
  it("a stale verdict is a FAIL even if it was OK", () => {
    const now = Date.now();
    const r = scheduleResult({ ts: now - t.scheduleStaleMs - 60_000, ok: true, sig: "ok", summary: "x" }, t, now);
    expect(r.ok).toBe(false);
    expect(r.reason).toContain("STALE");
  });
  it("a fresh OK verdict passes (control)", () => {
    const now = Date.now();
    expect(scheduleResult({ ts: now, ok: true, sig: "ok", summary: "x" }, t, now).ok).toBe(true);
  });
  it("names no repository in its url", () => {
    expect(scheduleResult(null, t, Date.now()).url).toBe("https://api.github.com/repos/.../actions/runs");
  });
});
