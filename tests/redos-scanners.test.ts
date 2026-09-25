import { describe, expect, it } from "vitest";
import { stripTrailingSlashes, unwrapAngleAddr } from "../src/index";

// The exact regexes these scanners replaced (js/polynomial-redos, CodeQL high). They are kept HERE,
// in the test, as the differential reference: the contract is "same answer, linear time", and a
// reference you can run is the only way to keep the first half of that honest. Do NOT move these
// back into src/.
const OLD_TRAILING_SLASH_RE = /\/+$/;
const OLD_ANGLE_ADDR_RE = /<([^>]+)>/;
const oldStrip = (s: string): string => s.replace(OLD_TRAILING_SLASH_RE, "");
const oldUnwrap = (t: string): string => {
  const m = t.match(OLD_ANGLE_ADDR_RE);
  return m ? m[1].trim() : t;
};

// One shared corpus for both scanners: real shapes, empty/degenerate cases, and the malformed ones
// where a naive rewrite silently diverges (the "a<>b<c>" pair-skipping case in particular).
const CORPUS = [
  "",
  "/",
  "///",
  "a",
  "x/y/",
  "https://hc-ping.com/abc",
  "https://hc-ping.com/abc/",
  "https://hc-ping.com/abc///",
  "https://ntfy.sh",
  "https://ntfy.sh/",
  "https://ntfy.sh////",
  "noreply@skyphusion.org",
  "Fleet Pusher <noreply@skyphusion.org>",
  "<noreply@skyphusion.org>",
  "  <noreply@skyphusion.org>  ",
  "<>",
  "a<>b<c>",
  "a<b<c>d",
  "<<<<",
  "nope <",
  "> <a@b>",
  "<a>><b>",
];

describe("stripTrailingSlashes", () => {
  it("matches the regex it replaced on every corpus entry", () => {
    for (const s of CORPUS) expect(stripTrailingSlashes(s)).toBe(oldStrip(s));
  });
  it("strips one, many, and zero trailing slashes", () => {
    expect(stripTrailingSlashes("https://ntfy.sh/")).toBe("https://ntfy.sh");
    expect(stripTrailingSlashes("https://ntfy.sh////")).toBe("https://ntfy.sh");
    expect(stripTrailingSlashes("https://ntfy.sh")).toBe("https://ntfy.sh");
  });
  it("leaves interior slashes alone and collapses an all-slash string to empty", () => {
    expect(stripTrailingSlashes("https://hc-ping.com/abc//")).toBe("https://hc-ping.com/abc");
    expect(stripTrailingSlashes("////")).toBe("");
    expect(stripTrailingSlashes("")).toBe("");
  });
});

describe("unwrapAngleAddr", () => {
  it("matches the regex it replaced on every corpus entry", () => {
    for (const s of CORPUS) expect(unwrapAngleAddr(s)).toBe(oldUnwrap(s));
  });
  it("unwraps a display-name wrapper and passes a bare address through", () => {
    expect(unwrapAngleAddr("fleet pusher <noreply@skyphusion.org>")).toBe("noreply@skyphusion.org");
    expect(unwrapAngleAddr("noreply@skyphusion.org")).toBe("noreply@skyphusion.org");
  });
  it("skips an empty <> pair exactly as the regex did", () => {
    expect(unwrapAngleAddr("a<>b<c>")).toBe("c");
    expect(unwrapAngleAddr("<>")).toBe("<>");
  });
  it("returns the input unchanged when there is no closing bracket", () => {
    expect(unwrapAngleAddr("<<<<")).toBe("<<<<");
    expect(unwrapAngleAddr("nope <")).toBe("nope <");
  });
});

// THE DoS GATE. This is the check that can actually go red: on this Worker (node v26 / V8, the same
// backtracking engine class workerd runs) the regexes these scanners replaced took 329ms and 333ms
// on a 32k input, rising ~4x per doubling, while the scanners are flat below 0.001ms. The budget is
// 250ms for BOTH scanners over FOUR pathological inputs, which is ~5 orders of magnitude of
// headroom for a loaded CI runner and still an order of magnitude BELOW a single one of the old
// regex calls. Reintroduce a quadratic regex at either site and this fails. It is not a
// micro-benchmark and must never be tightened into one.
describe("linear on pathological input (ReDoS regression gate)", () => {
  it("stays under budget where the old regexes went quadratic", () => {
    const n = 32_000;
    const slashRun = "/".repeat(n) + "x"; // every start position is a doomed candidate
    const angleRun = "<".repeat(n); // "[^>]" also matched "<", so every "<" was a start
    const angleEq = "<" + "<=".repeat(n); // CodeQL's own witness for the angle regex
    const slashLead = "/".repeat(n); // all-slash: the accepting path, not just the rejecting one

    const t0 = performance.now();
    const a = stripTrailingSlashes(slashRun);
    const b = unwrapAngleAddr(angleRun);
    const c = unwrapAngleAddr(angleEq);
    const d = stripTrailingSlashes(slashLead);
    const elapsed = performance.now() - t0;

    // Assert the ANSWERS too: a fast wrong answer is not a fix.
    expect(a).toBe(slashRun);
    expect(b).toBe(angleRun);
    expect(c).toBe(angleEq);
    expect(d).toBe("");
    expect(elapsed).toBeLessThan(250);
  });
});
