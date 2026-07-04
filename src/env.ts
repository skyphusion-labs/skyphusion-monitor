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
}
