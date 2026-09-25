// The alert channel is the one thing in this Worker that cannot be allowed to
// fail quietly: every other defect surfaces as an alert, and a defect in
// alerting surfaces as silence. These tests exist because the original guard
// refused to publish unless NTFY_TOKEN was set, which meant that repointing to
// ntfy.sh (where there is no token) would have muted the monitor completely
// while /health, the cron, and the HC dead-man all stayed green. Before trusting
// a green board, the question is what it structurally cannot see; a muted
// notify() is exactly that, so it gets a test that goes red on it.
import { describe, expect, it } from "vitest";
import { notifyTarget } from "../src/index";
import type { Env } from "../src/env";

const base = { NTFY_URL: "https://ntfy.sh", MONITOR_TOPIC: "topic-abc" } as unknown as Env;

describe("notifyTarget (the alert channel)", () => {
  it("PUBLISHES with no NTFY_TOKEN -- the ntfy.sh case, and the regression that muted the Worker", () => {
    const t = notifyTarget(base);
    expect(t).not.toBeNull();
    expect(t!.url).toBe("https://ntfy.sh/topic-abc");
    // No token means no Authorization header, NOT no request.
    expect(t!.authHeaders).toEqual({});
  });

  it("treats an empty-string token the same as unset (a blank secret must not mute it)", () => {
    const t = notifyTarget({ ...base, NTFY_TOKEN: "   " } as unknown as Env);
    expect(t).not.toBeNull();
    expect(t!.authHeaders).toEqual({});
  });

  it("attaches bearer auth when a token IS present (authenticated ntfy servers still work)", () => {
    const t = notifyTarget({ ...base, NTFY_TOKEN: "tk_example" } as unknown as Env);
    expect(t!.authHeaders).toEqual({ Authorization: "Bearer tk_example" });
  });

  it("trims a trailing slash on the base url so the topic path cannot double up", () => {
    const t = notifyTarget({ ...base, NTFY_URL: "https://ntfy.sh/" } as unknown as Env);
    expect(t!.url).toBe("https://ntfy.sh/topic-abc");
  });

  // The negative half. These prove the function CAN return null, so the
  // positive assertions above are not simply a function that always answers yes.
  it("returns null when the topic is missing (nothing to publish to)", () => {
    expect(notifyTarget({ NTFY_URL: "https://ntfy.sh" } as unknown as Env)).toBeNull();
  });

  it("returns null when the url is missing", () => {
    expect(notifyTarget({ MONITOR_TOPIC: "topic-abc" } as unknown as Env)).toBeNull();
  });

  it("returns null on whitespace-only config (a secret put with a stray newline)", () => {
    expect(notifyTarget({ NTFY_URL: " ", MONITOR_TOPIC: " " } as unknown as Env)).toBeNull();
  });
});
