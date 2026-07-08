export type CheckKind = "uptime" | "posture";

export interface CheckConfig {
  name: string;
  url: string;
  ok: number[];
  kind: CheckKind;
}

/** Returns true when an HTTP status is in the probe's allowed set. */
export function statusMatches(status: number, expected: number[]): boolean {
  return expected.includes(status);
}

/** Static validation for monitor probe definitions (no network). */
export function isValidCheck(c: CheckConfig): boolean {
  if (!c.name.trim()) return false;
  if (!c.url.startsWith("https://")) return false;
  if (!c.ok.length) return false;
  if (c.kind !== "uptime" && c.kind !== "posture") return false;
  return true;
}

export function uniqueCheckNames(checks: CheckConfig[]): boolean {
  const names = checks.map((c) => c.name);
  return names.length === new Set(names).size;
}
