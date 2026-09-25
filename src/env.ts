// Hand-authored Env (we do not generate worker types). Mirror every wrangler binding here.
export interface Env {
  // ntfy alerting. REPOINTED to public ntfy.sh 2026-09-25: the self-hosted
  // ntfy.skyphusion.org died with the Hetzner fleet, and this path must be
  // cloud -> cloud -> phone so it still works when we host nothing at all. An
  // alert channel that depends on our own infrastructure is not an alert
  // channel; it is a second thing to lose in the same outage.
  NTFY_URL: string;        // var, https://ntfy.sh
  // A SECRET, not a var, because this repo is PUBLIC. An unauthenticated ntfy.sh
  // topic has no access control other than its NAME, so a topic in a tracked
  // file lets anyone page the phone or, worse, forge a reassuring message.
  // Set via `wrangler secret put MONITOR_TOPIC`.
  MONITOR_TOPIC: string;   // secret
  // OPTIONAL. Unset is the NORMAL state on ntfy.sh, and alerting must work
  // without it; see notifyTarget() in src/index.ts for why requiring a token
  // silently muted every alert.
  NTFY_TOKEN?: string;     // secret, optional (authenticated ntfy servers only)
  // gate for the manual /run fetch endpoint (empty = disabled)
  RUN_KEY: string;         // var
  // Last-run state for the /health dead-man's-switch.
  MONITOR_STATE: KVNamespace;
  // delivery dead-man (#278): the HC.io check PING url (per-function -- NOT the mgmt key).
  // Set via `wrangler secret put HC_DEADMAN_PING_URL`. Empty/unset -> the email() handler no-ops.
  HC_DEADMAN_PING_URL: string; // secret
  // scheduled-run dead-man (monitor#3 part 1): the HC.io check PING url for the CRON.
  // scheduled() GETs it after each COMPLETED run; if the cron stops firing (worker broken,
  // account/CF outage), HC.io pages that the MONITOR itself is down. Set via
  // `wrangler secret put HC_CRON_PING_URL`. Empty/unset -> scheduled() skips the ping.
  // Per-function: the ping url ONLY, never the HC.io mgmt key. DISTINCT from the email
  // delivery dead-man (HC_DEADMAN_PING_URL, #278).
  HC_CRON_PING_URL: string; // secret
  // TLS cert-expiry probe (monitor#3 part 2): READ-scoped CF API token (Zone Read + SSL and
  // Certificates Read ONLY -- per-function, never the account admin token). Set via
  // `wrangler secret put CF_CERT_READ_TOKEN`. Empty/unset -> the cert probe no-ops.
  CF_CERT_READ_TOKEN: string; // secret
  // workers.dev coverage sweep (fc#1194 / fc#1180 F2): READ-scoped CF API token carrying
  // Account > Workers Scripts > Read ONLY -- per-function, never the deploy token and never
  // the shared crew token (that one has full data-plane WRITE reach and has no business
  // inside an internet-facing Worker). Set via `wrangler secret put CF_WORKERS_READ_TOKEN`.
  // Unset -> the coverage verdict is UNKNOWN, which FAILS (posture) rather than no-opping:
  // an absent credential must never read as "no Workers are exposed".
  CF_WORKERS_READ_TOKEN: string; // secret
  // The account id the coverage sweep enumerates. A SECRET rather than a var because this
  // repo is PUBLIC and the standing convention is that account_id is never hardcoded
  // (wrangler itself reads it from CLOUDFLARE_ACCOUNT_ID at deploy time, which does not
  // reach the runtime). Set via `wrangler secret put CF_ACCOUNT_ID`.
  CF_ACCOUNT_ID: string; // secret

  // ---- tunables (monitor#42): every knob is a var with a safe default in src/config.ts;
  // ---- all optional so an unset var can never break a run. Values are strings (wrangler vars).
  FETCH_TIMEOUT_MS?: string;         // per-probe fetch timeout (default 12000)
  RETRY_DELAY_MS?: string;           // delay before the single retry (default 1500)
  HEALTH_STALE_MIN?: string;         // /health staleness window in minutes (default 12)
  CERT_WARN_DAYS?: string;           // warn when a cert expires within N days (default 14)
  CERT_CHECK_INTERVAL_HOURS?: string; // cert sweep cadence in hours (default 20; keep <24)
  WORKERSDEV_SWEEP_INTERVAL_MIN?: string; // workers.dev coverage sweep cadence (default 60)
  DEADMAN_FROM?: string;             // allowed envelope sender for the delivery dead-man
  PROBE_USER_AGENT?: string;         // probe User-Agent override
}
