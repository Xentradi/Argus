# Argus

Argus is a self-hosted uptime monitoring service with:

- `ping`, `HTTP`, or `keyword` checks per monitor
- `60s` normal interval
- `3` confirmation retries at `5s` before down alerting
- `15s` checks while down
- `3` confirmation retries at `5s` before recovery alerting
- one down alert + one recovery alert per incident
- per-monitor Slack or Discord webhook destination
- monitor grouping (for company-based organization in UI)
- web UI protected by username/password + TOTP MFA
- SQLite persistence with incident/event retention of 3 years

## Check Logic

- **Normal state**: check every 60 seconds.
- **Failure candidate**: if a check fails, run 3 additional checks spaced 5 seconds apart.
  - If all retries fail, mark monitor `down`, open incident, send down alert, switch to 15-second interval.
  - If any retry succeeds, stay `up` and return to 60-second interval.
- **Down state**: check every 15 seconds.
- **Recovery candidate**: if a down monitor succeeds once, run 3 additional checks spaced 5 seconds apart.
  - If all retries succeed, mark monitor `up`, close incident, send recovery alert, switch to 60-second interval.
  - If any retry fails, remain `down` and continue 15-second checks.

## HTTP 200 vs 2xx

You can choose per monitor (default is `Any HTTP 2xx`):

- `Only HTTP 200` (strict; best when endpoint should return exactly 200)
- `Any HTTP 2xx` (more flexible; often better for API/health endpoints)

For most health endpoints, `2xx` is generally the better default. For pages that must return exactly `200`, use `200`.

## Requirements

- Node.js 18+
- Network access from this server to monitored hosts and webhook endpoints
- `ping` binary installed on the monitoring host for ICMP checks

## Install

```bash
npm install
```

## Run (dev)

```bash
npm start
```

Then open `http://localhost:3000`.

On first launch, you will be redirected to `/setup` to create the admin user and enroll TOTP.

## Run Tests

```bash
npm test
```

## API (Key Auth + Swagger)

Argus provides a key-authenticated API under `/api/v1` with user ownership enforcement. A key can only read or mutate that key owner’s monitors/groups/status pages/incidents/events.

Create a key for an existing user:

```bash
npm run create-api-key -- <username> [key-name]
```

Use the returned token as a bearer token:

```bash
Authorization: Bearer argus_<key-id>.<secret>
```

Swagger/OpenAPI docs:

- OpenAPI JSON: `/api/openapi.json`
- Swagger UI: `/api/docs`

## Smoke Checks

Runs one-off checks from a local JSON file (not committed):

```bash
npm run smoke ./local/smoke-targets.json
```

Example `./local/smoke-targets.json`:

```json
[
  {
    "name": "CompanyA Website",
    "checkType": "http",
    "url": "https://example.com/health",
    "httpStatusMode": "2xx",
    "timeoutMs": 10000
  },
  {
    "name": "CompanyA Gateway",
    "checkType": "ping",
    "host": "203.0.113.10"
  }
]
```

## Seed Monitors

Creates/updates monitors from a local JSON file (not committed):

```bash
npm run seed ./local/seed-monitors.json
```

Use local files so host and webhook data stay out of git history.

Example `./local/seed-monitors.json`:

```json
[
  {
    "name": "CompanyA Website",
    "groupName": "CompanyA",
    "checkType": "http",
    "url": "https://example.com/health",
    "httpStatusMode": "2xx",
    "webhookType": "slack",
    "webhookUrl": "https://example.invalid/webhook",
    "active": true
  }
]
```

## Run with PM2

```bash
pm2 start ecosystem.config.js
pm2 save
pm2 startup
```

## Environment Variables

- `PORT` (default: `3000`)
- `DB_FILE` (default: `./data/argus.db`)
- `RETENTION_DAYS` (default: `1095`)
- `NORMAL_INTERVAL_MS` (default: `60000`)
- `DOWN_INTERVAL_MS` (default: `15000`)
- `CONFIRMATION_RETRIES` (default: `3`)
- `CONFIRMATION_RETRY_INTERVAL_MS` (default: `5000`)
- `DEFAULT_TIMEOUT_MS` (default: `10000`)
- `WEBHOOK_DISPLAY_NAME` (default: `Argus`)
- `WEBHOOK_PUBLIC_BASE_URL` (default: `http://127.0.0.1:<PORT>`)
- `WEBHOOK_ICON_PATH` (default: `/img/argus-logo.png`)
- `WEBHOOK_ICON_URL` (default: empty)
- `ALERT_TIMEZONE` (default: `Pacific/Honolulu`, i.e. GMT-10)
- `SESSION_SECRET` (optional override; otherwise persisted in SQLite)
- `SESSION_DB_FILE` (default: `argus-sessions.sqlite`, stored in the same directory as `DB_FILE`)

## Data Retention

- Incidents are retained for 3 years by default (`RETENTION_DAYS=1095`).
- Events are retained for 3 years by default.
- Pruning runs at startup and daily.

## Notes

- For HTTPS checks, each monitor can either:
  - treat TLS certificate errors as failures, or
  - ignore certificate validation and continue as up.
- Keyword checks support case-sensitive or case-insensitive matching per monitor.
- Slack alerts send `username=Argus` and `icon_url` by default.
- Discord alerts send `username=Argus` and `avatar_url` by default.
- If you override with `WEBHOOK_PUBLIC_BASE_URL`, that URL must be reachable from the internet by Slack/Discord servers.
