// Hand-authored Env (we do not generate worker types). Mirror every wrangler binding here.
export interface Env {
  // PRIMARY alert transport: TELEGRAM, via the bot Conrad already runs
  // (`skyphusion-gatus`). His ruling on fc#2172, 2026-09-26: "Telegram as the
  // primary with postern email as the secondary". The previous target was public
  // ntfy.sh; he DECLINED it as a NEW vendor for a problem two already-trusted ones
  // solve, and estate alert bodies name hostnames, services and failure modes,
  // which is exactly the topology the pre-public scans exist to keep out of third
  // party hands. The path is still cloud -> cloud -> phone, so it survives the loss
  // of everything we host: an alert channel that depends on our own infrastructure
  // is not an alert channel, it is a second thing to lose in the same outage.
  //
  // The names are deliberately the ones the existing fleet runbook
  // (`docs/runbooks/gatus-multi-channel-alerts.md` in fleet-chezmoi) already used,
  // because this is REUSE of the one bot. A second bot pointed at the same human is
  // two things to keep alive and one of them rots silently.
  //
  // BOTH are SECRETS, not vars, because this repo is PUBLIC: the token can post as
  // the bot, and the chat id identifies a private chat. Set with
  // `wrangler secret put GATUS_TELEGRAM_BOT_TOKEN` and `... GATUS_TELEGRAM_CHAT_ID`.
  // Either one unset means alerting is MUTE, which is now a /health FAILURE and
  // suppresses the cron dead-man ping; see alertTransport() in src/index.ts.
  GATUS_TELEGRAM_BOT_TOKEN: string; // secret
  GATUS_TELEGRAM_CHAT_ID: string;   // secret
  // Var, so a test can exercise alertTransport() without holding either secret.
  // Defaults to https://api.telegram.org when unset or blank.
  TELEGRAM_API_BASE?: string;       // var
  //
  // SECONDARY leg (postern email) is NOT wired here yet, deliberately. It is
  // blocked on fc#2093: postern outbound send is BROKEN today (the deploy smoke
  // returns E_DELIVERY_FAILED / relay upstream send failed 530, because the relay
  // was a fleet host). Declaring an unusable binding now would add a channel that
  // is mute from birth, and "secondary" would mean simultaneous-and-unwatched.
  // Wire it in the change that closes fc#2093, and prove it with a real send.
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
