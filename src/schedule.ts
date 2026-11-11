// CI schedule liveness: is GitHub Actions STARTING runs at all in the watched repository?
//
// WHY THIS LIVES HERE AND NOT IN THAT REPOSITORY. Measured 2026-11-11: on whole days (10-21 to
// 10-28 and 10-31 to 11-08) every run in the watched repository, scheduled, push and
// pull_request alike, ended `startup_failure` before any job ran. The in-repository freshness
// audit is itself a scheduled workflow in that repository, so it failed to start on exactly the
// same days and said nothing for seventeen of them. A monitor that shares the fate of what it
// monitors is not a monitor. This check runs on Cloudflare and reads the GitHub API, so it does
// not depend on the thing it watches being able to start.
//
// SCOPE. This answers ONE question: did Actions start runs in the last window. Per-workflow
// tolerance stays with the in-repository audit, which works whenever Actions does.
//
// NO REPOSITORY NAME IN THIS PUBLIC REPO. The owner/repo comes from a Worker secret
// (GH_SCHEDULE_REPO) and every string this module produces says "CI schedule", never a name.

/** The counts the sweep reads from the GitHub API for one window. */
export interface ScheduleCounts {
  /** Runs of any event in the window that ended startup_failure (filtered query, total_count). */
  startupFailures: number;
  /** Scheduled runs in the window (filtered query, total_count). */
  scheduledTotal: number;
  /** Scheduled runs in the window that ended startup_failure (filtered query, total_count). */
  scheduledStartupFailures: number;
  /**
   * CONTROL for the filtered queries: how many of the latest unfiltered runs (one page, any
   * time) ended startup_failure. GitHub answers 0 for a status filter it does not understand
   * (measured: status=bogus_value -> total_count 0), so a filter that stopped working would read
   * as "no startup failures". If the unfiltered sample shows them inside the window and the
   * filter shows none, the filter is broken and the verdict is UNMEASURED, never clean.
   */
  sampleStartupFailuresInWindow: number;
}

export interface ScheduleVerdict {
  ok: boolean;
  /** Stable for a given failure shape, so a standing failure is recognisable across sweeps. */
  sig: "ok" | "start-failures" | "no-scheduled-run" | "filter-disagrees" | "bad-counts";
  summary: string;
}

const isCount = (n: unknown): n is number => typeof n === "number" && Number.isInteger(n) && n >= 0;

export function assessSchedule(c: ScheduleCounts, windowHours: number): ScheduleVerdict {
  const fields = [c.startupFailures, c.scheduledTotal, c.scheduledStartupFailures, c.sampleStartupFailuresInWindow];
  if (!fields.every(isCount) || c.scheduledStartupFailures > c.scheduledTotal || c.scheduledStartupFailures > c.startupFailures) {
    return { ok: false, sig: "bad-counts", summary: "CI schedule: the API returned counts that do not add up -- state UNMEASURED, not clean" };
  }
  if (c.sampleStartupFailuresInWindow > 0 && c.startupFailures === 0) {
    return { ok: false, sig: "filter-disagrees",
      summary: `CI schedule: ${c.sampleStartupFailuresInWindow} run(s) in the latest sample failed to start but the filtered count reads 0 -- the filter is not measuring, state UNMEASURED` };
  }
  const loaded = c.scheduledTotal - c.scheduledStartupFailures;
  if (c.startupFailures > 0) {
    return { ok: false, sig: "start-failures",
      summary: `CI schedule: ${c.startupFailures} run(s) failed to start in the last ${windowHours}h (${c.scheduledStartupFailures} of ${c.scheduledTotal} scheduled); runs are not reaching a job` };
  }
  if (loaded === 0) {
    return { ok: false, sig: "no-scheduled-run",
      summary: `CI schedule: no scheduled run started in the last ${windowHours}h; scheduled checks there are not running` };
  }
  return { ok: true, sig: "ok", summary: `CI schedule: ${loaded} scheduled run(s) started in the last ${windowHours}h, none failed to start` };
}

/** "owner/repo", both halves GitHub-legal, or null. Validated so a mistyped secret fails loudly. */
export function parseRepo(raw: string | undefined): string | null {
  const s = (raw ?? "").trim();
  const m = /^([A-Za-z0-9-]{1,39})\/([A-Za-z0-9._-]{1,100})$/.exec(s);
  return m ? `${m[1]}/${m[2]}` : null;
}
