# Runbook

How to deploy, configure and operate the scanning service. Commands assume the repository root.

## Deploy

```bash
docker build -t defi-sentinel:1.0.0 .
python -m defisentinel.ops keygen            # one key per CI pipeline, viewer and monitor
docker run -d --name defisentinel -p 8008:8008 -v defisentinel-data:/data \
  -e DEFISENTINEL_KEYS_FILE=/run/secrets/defisentinel-keys.json \
  defi-sentinel:1.0.0
curl -fsS http://127.0.0.1:8008/readyz
```

The image runs in production mode as a non-root user with its SQLite database in `/data`. It refuses
to start, and logs why, without keys or a database URL. Terminate TLS in front of it. For several
replicas use Postgres.

A CI pipeline then posts its sources:

```bash
curl -fsS -H "x-api-key: $KEY" -H 'content-type: application/json' \
  -d '{"files": {"Vault.sol": "..."}, "fail_on": "high", "label": "repo@commit"}' \
  https://scanner.example/v1/scan
```

and fails the build when `passed` is false.

## Configure

| Variable | Required in production | Meaning |
|---|---|---|
| `DEFISENTINEL_ENV` | — | `development` (default) or `production` |
| `DEFISENTINEL_API_KEYS` / `DEFISENTINEL_KEYS_FILE` | yes | JSON `{"sha256:<hex>": {"user": "...", "role": "..."}}`. Roles: `scanner` (scan, read), `viewer` (read), `monitor` (`/metrics`), `admin` |
| `DEFISENTINEL_DATABASE_URL` | yes | `sqlite:////data/defisentinel.db` or `postgresql://...` (development default: in memory) |
| `DEFISENTINEL_HOST`, `DEFISENTINEL_PORT` | — | default `127.0.0.1:8008`; a non-loopback address needs API keys |
| `DEFISENTINEL_RATE_LIMIT`, `DEFISENTINEL_MAX_BODY_BYTES` | — | default 120/min per client, 2,000,000 bytes |
| `DEFISENTINEL_CORS_ORIGINS`, `DEFISENTINEL_LOG_LEVEL` | — | none by default; `INFO` |

## Watch

- `GET /healthz`: process up. `GET /readyz`: database answers.
- `GET /metrics` (role `monitor`): `http_requests_total`, `http_request_duration_seconds`,
  `errors_total`, `defisentinel_decisions_total{decision="critical|high|medium|low|info|scan_passed|scan_failed"}`.
- Logs: JSON lines with `request_id`, also returned in `X-Request-ID`.

Suggested alerts: `/readyz` failing; p95 `/v1/scan` latency above 10 s; 5xx rising.

## Rotate keys

Add the new hash, restart, hand over the key, remove the old hash, restart. Remove a hash and
restart to revoke at once.

## Back up and restore

```bash
docker exec defisentinel python -c "import sqlite3; s=sqlite3.connect('/data/defisentinel.db'); d=sqlite3.connect('/data/backup.db'); s.backup(d)"
docker cp defisentinel:/data/backup.db ./defisentinel-$(date +%F).db
```

Restore: stop the container, put the backup at `/data/defisentinel.db`, start it, check `/readyz`
and `GET /v1/scans`. Postgres: `pg_dump` / `pg_restore`; migrations run on start or with
`python -m defisentinel migrate`.

## Incidents

1. **Leaked API key.** Remove its hash and restart; check scans requested under that user.
2. **A deployed contract was exploited through a bug class the scanner covers.** Find its scans by
   label or file hash, add the pattern to the detectors with a test, and re-score SmartBugs to report
   the change honestly.
