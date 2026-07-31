// Probe inventory + tunables loading (monitor#42). The inventory is the
// committed config/monitors.json (validated in CI by tests/config.test.ts and
// bundled at build); every operational knob is a wrangler var with a safe
// default here. src/index.ts is pure engine: zero estate hostnames, zero
// magic numbers.
import type { Env } from "./env";
import { type CheckConfig, validateChecks } from "./validate";
import { type WorkersDevPolicy, validateWorkersDevPolicy } from "./coverage";
import monitorsJson from "../config/monitors.json";

export interface LoadedConfig {
  checks: CheckConfig[];
  /** Non-empty = the inventory is unusable; the engine must fail CLOSED (alert, not skip silently). */
  errors: string[];
}

export function loadChecks(): LoadedConfig {
  const checks = (monitorsJson as { checks?: unknown }).checks;
  const errors = validateChecks(checks);
  return { checks: errors.length ? [] : (checks as CheckConfig[]), errors };
}

export interface LoadedPolicy {
  policy: WorkersDevPolicy;
  /** Non-empty = the allowance policy is unusable; same fail-closed path as a bad inventory. */
  errors: string[];
}

/**
 * The workers.dev ALLOWANCE policy (fc#1194). A missing `workersDev` block is an
 * error, not an empty allowance: silently assessing against nothing is how a
 * coverage check becomes a check that can only pass.
 */
export function loadWorkersDevPolicy(): LoadedPolicy {
  const raw = (monitorsJson as { workersDev?: unknown }).workersDev;
  if (raw === undefined) return { policy: { allowed: [] }, errors: ["workersDev block missing from config/monitors.json"] };
  const errors = validateWorkersDevPolicy(raw);
  return { policy: errors.length ? { allowed: [] } : (raw as WorkersDevPolicy), errors };
}

export interface Tunables {
  fetchTimeoutMs: number;
  retryDelayMs: number;
  healthStaleMs: number;
  certWarnDays: number;
  certCheckIntervalMs: number;
  workersDevSweepIntervalMs: number;
  /**
   * Verdict staleness window. DELIBERATELY NOT A VAR: it is the dead-man for the
   * coverage sweep itself, and a knob that can be set to "never stale" is a knob
   * that can silence it. Derived as 3x the sweep interval so it cannot be
   * misconfigured independently of the cadence it guards.
   */
  workersDevStaleMs: number;
  deadmanFrom: string;
  userAgent: string;
}

function intVar(raw: string | undefined, fallback: number): number {
  const n = Number(raw);
  return Number.isFinite(n) && n > 0 ? n : fallback;
}

/** Every tunable comes from a var with a safe default; a bad/missing var can never break a run. */
export function tunables(env: Env): Tunables {
  const workersDevSweepIntervalMs = intVar(env.WORKERSDEV_SWEEP_INTERVAL_MIN, 60) * 60_000;
  return {
    fetchTimeoutMs: intVar(env.FETCH_TIMEOUT_MS, 12_000),
    retryDelayMs: intVar(env.RETRY_DELAY_MS, 1_500),
    healthStaleMs: intVar(env.HEALTH_STALE_MIN, 12) * 60_000,
    certWarnDays: intVar(env.CERT_WARN_DAYS, 14),
    // <24h default so cron jitter cannot skip a day.
    certCheckIntervalMs: intVar(env.CERT_CHECK_INTERVAL_HOURS, 20) * 3_600_000,
    workersDevSweepIntervalMs,
    workersDevStaleMs: workersDevSweepIntervalMs * 3,
    deadmanFrom: env.DEADMAN_FROM?.trim() || "noreply@skyphusion.org",
    userAgent: env.PROBE_USER_AGENT?.trim() || "skyphusion-monitor/1 (+external posture probe)",
  };
}
