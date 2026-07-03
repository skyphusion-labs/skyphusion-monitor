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
}
