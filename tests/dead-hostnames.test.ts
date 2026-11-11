// fc#2080: a check on a dead hostname is a guaranteed permanent failure that
// masks real outages. These hostnames were measured NXDOMAIN (1.1.1.1 and
// 8.8.8.8) and their origins are retired; they must never reappear in the
// shipped inventory. Re-adding one needs a fresh resolve AND removal from here.
import { describe, expect, it } from "vitest";
import { loadChecks } from "../src/config";

const DEAD_HOSTNAMES = [
  // Retired Hetzner fleet surfaces (NXDOMAIN, fleet cut 2026-09-24)
  "auth.skyphusion.org",
  "ntfy.skyphusion.org",
  "chat.skyphusion.org",
  "chat-plus.skyphusion.org",
  "search.skyphusion.org",
  "grafana.skyphusion.org",
  // Umami retired; skyphusion.net and skyphusion.org dropped the script 2026-11-11
  "analytics.skyphusion.org",
  // Gatus status page and its load balancer retired
  "status.skyphusion.org",
  // Demo removed entirely (monitor#112)
  "demo.vivijure.com",
];

describe("shipped inventory has no dead-subject checks (fc#2080)", () => {
  it("no check targets a retired hostname", () => {
    const { checks, errors } = loadChecks();
    expect(errors).toEqual([]);
    const hosts = checks.map((c) => ({ name: c.name, host: new URL(c.url).hostname }));
    const hits = hosts.filter((h) => DEAD_HOSTNAMES.includes(h.host.toLowerCase()));
    expect(hits).toEqual([]);
  });

  it("the guard can go red: a dead host in a check list is detected", () => {
    const sample = [{ name: "x", host: new URL("https://analytics.skyphusion.org/t.js").hostname }];
    expect(sample.filter((h) => DEAD_HOSTNAMES.includes(h.host))).toHaveLength(1);
  });
});
