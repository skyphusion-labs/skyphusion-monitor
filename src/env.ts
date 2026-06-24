// Hand-authored Env (we do not generate worker types). Mirror every wrangler binding here.
export interface Env {
  // ntfy alerting
  NTFY_URL: string;        // var, e.g. https://ntfy.skyphusion.org
  MONITOR_TOPIC: string;   // var, the ntfy topic to publish alerts to
  NTFY_TOKEN: string;      // secret: least-privilege ntfy publish token
  // gate for the manual /run fetch endpoint (empty = disabled)
  RUN_KEY: string;         // var
}
