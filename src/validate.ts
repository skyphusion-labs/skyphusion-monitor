export type CheckKind = "uptime" | "posture";

export interface CheckConfig {
  name: string;
  url: string;
  ok: number[]; // acceptable final status codes
  kind: CheckKind;
  note?: string;
  // A body containing any of these (exact substring) is a FAILURE even if the
  // status matched (catches "200 but serving sensitive JSON" auth bypass).
  bodyMustNotInclude?: string[];
  // Required response headers (lowercased name -> expected value).
  requireHeaders?: Record<string, string>;
  // Per-check fetch timeout override; falls back to the FETCH_TIMEOUT_MS var.
  timeoutMs?: number;
}

/** Returns true when an HTTP status is in the probe's allowed set. */
export function statusMatches(status: number, expected: number[]): boolean {
  return expected.includes(status);
}

/** Static validation for one monitor probe definition (no network). */
export function isValidCheck(c: CheckConfig): boolean {
  if (typeof c.name !== "string" || !c.name.trim()) return false;
  if (typeof c.url !== "string" || !c.url.startsWith("https://")) return false;
  if (!Array.isArray(c.ok) || !c.ok.length) return false;
  if (!c.ok.every((s) => Number.isInteger(s) && s >= 100 && s <= 1099)) return false;
  if (c.kind !== "uptime" && c.kind !== "posture") return false;
  if (c.bodyMustNotInclude !== undefined) {
    if (!Array.isArray(c.bodyMustNotInclude)) return false;
    if (!c.bodyMustNotInclude.every((m) => typeof m === "string" && m.length > 0)) return false;
  }
  if (c.requireHeaders !== undefined) {
    if (typeof c.requireHeaders !== "object" || c.requireHeaders === null) return false;
    for (const [h, v] of Object.entries(c.requireHeaders)) {
      if (!h.trim() || typeof v !== "string" || !v.trim()) return false;
    }
  }
  if (c.timeoutMs !== undefined && (!Number.isInteger(c.timeoutMs) || c.timeoutMs <= 0)) {
    return false;
  }
  return true;
}

export function uniqueCheckNames(checks: CheckConfig[]): boolean {
  const names = checks.map((c) => c.name);
  return names.length === new Set(names).size;
}

/** Validate a full probe inventory; returns human-readable errors (empty = valid). */
export function validateChecks(checks: unknown): string[] {
  const errors: string[] = [];
  if (!Array.isArray(checks)) return ["checks is not an array"];
  if (!checks.length) return ["checks is empty"];
  checks.forEach((c, i) => {
    if (!isValidCheck(c as CheckConfig)) {
      errors.push(`invalid check at index ${i}${(c as CheckConfig)?.name ? ` (${(c as CheckConfig).name})` : ""}`);
    }
  });
  if (!errors.length && !uniqueCheckNames(checks as CheckConfig[])) {
    errors.push("duplicate check names");
  }
  return errors;
}

export interface Assessment {
  ok: boolean;
  reason?: string;
}

/**
 * Pure response assessment (status + headers + body against one check), so the
 * engine's pass/fail logic is unit-testable without a network.
 */
export function assessResponse(
  c: CheckConfig,
  status: number,
  getHeader: (name: string) => string | null,
  body: string,
): Assessment {
  if (!statusMatches(status, c.ok)) {
    return { ok: false, reason: `status ${status} not in ${c.ok.join("/")}` };
  }
  if (c.requireHeaders) {
    for (const [h, want] of Object.entries(c.requireHeaders)) {
      const got = getHeader(h);
      if (!got || got.toLowerCase() !== want.toLowerCase()) {
        return { ok: false, reason: `header ${h}=${got ?? "(absent)"} want ${want}` };
      }
    }
  }
  if (c.bodyMustNotInclude?.length) {
    const hit = c.bodyMustNotInclude.find((s) => body.includes(s));
    if (hit) return { ok: false, reason: `body leaked marker ${JSON.stringify(hit)}` };
  }
  return { ok: true };
}
