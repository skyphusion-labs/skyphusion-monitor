import { describe, it, expect } from "vitest";
import { isSickFromLastRun } from "../src/index";

describe("isSickFromLastRun (#58)", () => {
  // The live failure shape: two uptime (or mixed) failures, zero posture findings.
  // Old derivation: (posture ?? failures) > 0 with posture=0 => 0 > 0 => false.
  it("is sick when failures > 0 and posture is 0 (the board-lie case)", () => {
    expect(isSickFromLastRun({ failures: 2, posture: 0 })).toBe(true);
  });

  it("is sick on posture findings alone", () => {
    expect(isSickFromLastRun({ failures: 1, posture: 1 })).toBe(true);
  });

  it("is sick on configError even with zero failures", () => {
    expect(isSickFromLastRun({ failures: 0, posture: 0, configError: true })).toBe(true);
  });

  it("is not sick when clean", () => {
    expect(isSickFromLastRun({ failures: 0, posture: 0 })).toBe(false);
    expect(isSickFromLastRun({ failures: 0 })).toBe(false);
  });

  // Pin the exact operator that bit: ?? must not be used as "prefer posture".
  it("CONTROL: the old (posture ?? failures) form is false on the live shape", () => {
    const last = { failures: 2, posture: 0 };
    const oldWrong = (last.posture ?? last.failures) > 0;
    expect(oldWrong).toBe(false);
    expect(isSickFromLastRun(last)).toBe(true);
  });
});
