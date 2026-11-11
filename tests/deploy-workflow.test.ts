// deploy.yml sets the SCHED.ci secrets (GH_ACTIONS_READ_TOKEN, GH_SCHEDULE_REPO) on the tag path.
//
// The token exists only as a GitHub Actions secret, so this step is the ONLY way it reaches the
// Worker. These assertions pin the properties that make that safe: tag path only, values through
// env and never through the script text, piped on stdin, presence-checked, never echoed.
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";

const wf = readFileSync(join(__dirname, "..", ".github", "workflows", "deploy.yml"), "utf8");

/** The text of one step, from its `- name:` line to the next `- ` step at the same indent. */
function step(name: string): string {
  const start = wf.indexOf(`- name: ${name}`);
  if (start < 0) return "";
  const rest = wf.slice(start + 1);
  const next = rest.search(/\n      - /);
  return next < 0 ? wf.slice(start) : wf.slice(start, start + 1 + next);
}

describe("deploy.yml sets the CI schedule secrets", () => {
  const s = step("Set the CI schedule secrets on the Worker");

  it("has the step, after the deploy", () => {
    expect(s).not.toBe("");
    expect(wf.indexOf("- name: Set the CI schedule secrets on the Worker")).toBeGreaterThan(wf.indexOf("- name: Deploy worker"));
  });
  it("runs on the v* tag path only", () => {
    expect(s).toContain("if: startsWith(github.ref, 'refs/tags/v')");
  });
  it("takes both values from secrets through env, never interpolated into the script", () => {
    expect(s).toContain("SCHED_TOKEN: ${{ secrets.SKYPHUSION_MONITOR_CI_SCHEDULE_READ }}");
    expect(s).toContain("SCHED_REPO: ${{ secrets.GH_SCHEDULE_REPO }}");
    const run = s.slice(s.indexOf("run: |"));
    expect(run).not.toMatch(/\$\{\{\s*secrets\./);
  });
  it("pipes each value on stdin to wrangler secret put", () => {
    expect(s).toContain(`printf '%s' "$SCHED_TOKEN" | npx wrangler secret put GH_ACTIONS_READ_TOKEN`);
    expect(s).toContain(`printf '%s' "$SCHED_REPO" | npx wrangler secret put GH_SCHEDULE_REPO`);
  });
  it("fails the step when either value is empty", () => {
    expect(s).toContain(`[ -n "\${SCHED_TOKEN:-}" ] || {`);
    expect(s).toContain(`[ -n "\${SCHED_REPO:-}" ] || {`);
    expect(s).toContain("set -euo pipefail");
  });
  it("never prints a value: presence words only", () => {
    expect(s).toContain("SCHED_TOKEN=${SCHED_TOKEN:+SET}");
    // No echo/printf of a raw value except the two stdin pipes asserted above.
    const lines = s.split("\n").filter((l) => /\$SCHED_(TOKEN|REPO)\b|\$\{SCHED_(TOKEN|REPO)\}/.test(l));
    for (const l of lines) expect(l, l).toMatch(/printf '%s' "\$SCHED_(TOKEN|REPO)" \| npx wrangler secret put/);
  });
});
