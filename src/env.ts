// Hand-authored Env (we do not generate worker types). Mirror every wrangler binding here.
export interface Env {
  // ntfy alerting
  NTFY_URL: string;        // var, e.g. https://ntfy.skyphusion.org
  MONITOR_TOPIC: string;   // var, the ntfy topic to publish alerts to
  NTFY_TOKEN: string;      // secret: least-privilege ntfy publish token
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

  // ---- tunables (monitor#42): every knob is a var with a safe default in src/config.ts;
  // ---- all optional so an unset var can never break a run. Values are strings (wrangler vars).
  FETCH_TIMEOUT_MS?: string;         // per-probe fetch timeout (default 12000)
  RETRY_DELAY_MS?: string;           // delay before the single retry (default 1500)
  HEALTH_STALE_MIN?: string;         // /health staleness window in minutes (default 12)
  CERT_WARN_DAYS?: string;           // warn when a cert expires within N days (default 14)
  CERT_CHECK_INTERVAL_HOURS?: string; // cert sweep cadence in hours (default 20; keep <24)
  DEADMAN_FROM?: string;             // allowed envelope sender for the delivery dead-man
  PROBE_USER_AGENT?: string;         // probe User-Agent override
}
