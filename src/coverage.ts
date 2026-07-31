// workers.dev coverage assessment (fc#1194 A1 / fc#1180 F2).
//
// WHY THIS IS NOT A PROBE. The monitor CANNOT probe a sibling *.workers.dev
// hostname: Cloudflare blocks Worker-to-workers.dev subrequests inside the same
// account and returns 404 `error code: 1042` for EVERY such name, whether the
// subdomain is enabled or disabled. Measured 2026-08-01 from a Worker in this
// account: sidvicious-search (ENABLED, 401 from outside), slate-search
// (ENABLED, 405), slate-logs (ENABLED, 401), grid-hub (DISABLED) and
// vivijure-studio (DISABLED) all returned an identical 404/1042; a control fetch
// of https://skyphusion.org/ (a Worker on a CUSTOM domain) returned a real 200,
// proving the prober works and that only the workers.dev band is blinded.
//
// So the four F1.* probe tripwires this replaces expected [404, 530, 1033] and
// matched 404 forever. They could not report the bad state on any Worker, at any
// coverage level. Detection has to come from the API, which is authoritative and
// vantage-independent.
//
// COVERAGE IS DERIVED, NOT DECLARED. The script list comes from the Cloudflare
// API, so a Worker deployed tomorrow is inside the assessment the moment it
// exists. The only declared half is the ALLOWANCE list: a Worker may keep
// workers.dev on if and only if config/monitors.json says so, with a reason and
// a pointer to what actually covers it. A stale allowance fails too, so the list
// cannot rot into a permanent silent pass.

export interface SubdomainState {
  script: string;
  /** Authoritative workers.dev state from the API. Never inferred. */
  enabled: boolean;
  /**
   * Preview-URL state (<version>-<script>.<subdomain>.workers.dev), the second
   * bypass surface. `null` = the API did not report a boolean; UNKNOWN is a
   * finding, never a quiet false.
   */
  previewsEnabled: boolean | null;
}

export interface WorkersDevAllowance {
  script: string;
  /** Why this Worker is allowed to answer on workers.dev. */
  reason: string;
  /** What actually covers it, since this monitor structurally cannot. */
  coverage: string;
}

export interface WorkersDevPolicy {
  allowed: WorkersDevAllowance[];
}

export interface CoverageFinding {
  code: CoverageCode;
  script: string;
  detail: string;
}

export type CoverageCode =
  | "enumeration-empty"
  | "workers-dev-undeclared"
  | "preview-urls-undeclared"
  | "preview-state-unknown"
  | "allowance-stale"
  | "allowance-without-script";

const SCRIPT_RE = /^[a-z0-9][a-z0-9._-]*$/;

/** Static validation of the allowance policy. Non-empty = the inventory is unusable. */
export function validateWorkersDevPolicy(raw: unknown): string[] {
  const errors: string[] = [];
  if (typeof raw !== "object" || raw === null || Array.isArray(raw)) {
    return ["workersDev is not an object"];
  }
  const allowed = (raw as { allowed?: unknown }).allowed;
  if (!Array.isArray(allowed)) return ["workersDev.allowed is not an array"];
  const seen = new Set<string>();
  allowed.forEach((a, i) => {
    const e = a as Partial<WorkersDevAllowance>;
    const where = `workersDev.allowed[${i}]${typeof e?.script === "string" ? ` (${e.script})` : ""}`;
    if (typeof e?.script !== "string" || !SCRIPT_RE.test(e.script)) {
      errors.push(`${where}: invalid script name`);
      return;
    }
    if (seen.has(e.script)) errors.push(`${where}: duplicate script`);
    seen.add(e.script);
    // A reason and a coverage pointer are load-bearing, not documentation: an
    // allowance with neither is an undocumented exception that outlives whoever
    // added it.
    if (typeof e.reason !== "string" || !e.reason.trim()) errors.push(`${where}: missing reason`);
    if (typeof e.coverage !== "string" || !e.coverage.trim()) errors.push(`${where}: missing coverage pointer`);
  });
  return errors;
}

/**
 * Assess the API-derived script census against the allowance policy.
 * Empty result = healthy. Every other return value is a posture failure.
 */
export function assessWorkersDevCoverage(
  states: SubdomainState[],
  policy: WorkersDevPolicy,
): CoverageFinding[] {
  // An account-scoped read that returns an empty success is indistinguishable
  // from a permission gap (fc#1180 F5: cfd_tunnel returned HTTP 200 total_count
  // 0 while 6 tunnels were live). Zero Workers is UNKNOWN, never clean.
  if (!states.length) {
    return [{
      code: "enumeration-empty",
      script: "(none)",
      detail: "CF API returned zero Workers; treated as UNKNOWN state, not as an empty account",
    }];
  }

  const allowedBy = new Map(policy.allowed.map((a) => [a.script, a]));
  const stateBy = new Map(states.map((s) => [s.script, s]));
  const findings: CoverageFinding[] = [];

  for (const s of states) {
    const allow = allowedBy.get(s.script);
    if (s.enabled && !allow) {
      findings.push({
        code: "workers-dev-undeclared",
        script: s.script,
        detail: "workers.dev is ENABLED with no allowance in config/monitors.json; Access binds a hostname and never covers *.workers.dev",
      });
    }
    if (s.previewsEnabled === null) {
      findings.push({
        code: "preview-state-unknown",
        script: s.script,
        detail: "the API did not report a boolean previews_enabled; unknown is not clean",
      });
    } else if (s.previewsEnabled && !allow) {
      findings.push({
        code: "preview-urls-undeclared",
        script: s.script,
        detail: "preview URLs are ENABLED with no allowance; <version>-<script>.workers.dev is a second uncovered hostname",
      });
    }
  }

  for (const a of policy.allowed) {
    const s = stateBy.get(a.script);
    if (!s) {
      findings.push({
        code: "allowance-without-script",
        script: a.script,
        detail: "allowance names a Worker that does not exist in the account; the allowance list is drifting from reality",
      });
      continue;
    }
    if (!s.enabled && !s.previewsEnabled) {
      findings.push({
        code: "allowance-stale",
        script: a.script,
        detail: "allowance is no longer needed (workers.dev and preview URLs are both off); remove it so the list cannot rot into a silent permanent pass",
      });
    }
  }

  // Deterministic order keeps the alert signature stable across runs.
  return findings.sort((x, y) => (x.script === y.script ? x.code.localeCompare(y.code) : x.script.localeCompare(y.script)));
}

/**
 * Stable signature of a finding set, so a STANDING failure can be re-alerted on
 * a slow cadence while a CHANGED failure set pages immediately.
 */
export function coverageSignature(findings: CoverageFinding[]): string {
  return findings.map((f) => `${f.script}:${f.code}`).join(",");
}

/** One-line human summary for the ntfy body and the /run payload. */
export function summarizeCoverage(findings: CoverageFinding[], scripts: number): string {
  if (!findings.length) return `${scripts} Worker(s) enumerated, all workers.dev state accounted for`;
  const head = findings.slice(0, 8).map((f) => `${f.code} ${f.script}`).join("; ");
  const tail = findings.length > 8 ? ` (+${findings.length - 8} more)` : "";
  return `${findings.length} finding(s) over ${scripts} Worker(s): ${head}${tail}`;
}
