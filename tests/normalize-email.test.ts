import { describe, expect, it } from "vitest";
import { normalizeEmailAddr } from "../src/index";

describe("normalizeEmailAddr", () => {
  it("lowercases bare addresses", () => {
    expect(normalizeEmailAddr("NoReply@Skyphusion.ORG")).toBe("noreply@skyphusion.org");
  });
  it("strips display-name wrappers", () => {
    expect(normalizeEmailAddr("Fleet Pusher <noreply@skyphusion.org>")).toBe(
      "noreply@skyphusion.org",
    );
  });
  it("trims whitespace", () => {
    expect(normalizeEmailAddr("  noreply@skyphusion.org  ")).toBe("noreply@skyphusion.org");
  });
  it("empty/null -> empty", () => {
    expect(normalizeEmailAddr("")).toBe("");
    expect(normalizeEmailAddr(null)).toBe("");
    expect(normalizeEmailAddr(undefined)).toBe("");
  });
});
