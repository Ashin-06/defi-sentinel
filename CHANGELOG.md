# Changelog

All notable changes to this project. Versions follow [semantic versioning](https://semver.org/).

## 1.0.0 — 2026-11-02

### Added
- A scanning API (`python -m defisentinel serve`): `POST /v1/scan` takes Solidity sources and
  returns findings, a summary and pass/fail against `fail_on`, as JSON or SARIF; `GET /v1/scans`
  and `GET /v1/scans/{id}` return the history. Sources are not stored, only each file's SHA-256.
- Scan history in SQLite, or Postgres through `DEFISENTINEL_DATABASE_URL`; numbered migrations and
  `python -m defisentinel migrate`.
- Settings from `DEFISENTINEL_*` environment variables, checked at startup.
  `DEFISENTINEL_ENV=production` refuses to start without hashed API keys and a database.
- Per-client API keys with roles (`scanner`, `viewer`, `monitor`, `admin`), stored as
  `sha256:<hex>`; `python -m defisentinel.ops keygen` makes new ones.
- Per-client rate limit, body cap, security headers, CORS only for listed origins, validation
  errors that don't echo input; JSON logs with request IDs; `/healthz`, `/readyz` and Prometheus
  `/metrics` (`defisentinel_decisions_total` by finding severity and scan outcome).
- `pyproject.toml` with a `defisentinel` console command, pinned `requirements.lock` /
  `requirements-dev.lock`, a container image (slim Python 3.12, non-root, health check).
- CI now runs ruff, bandit, pip-audit and pytest with coverage before the contract scan.
- `SECURITY.md`, `docs/threat-model.md`, `docs/runbook.md`, MIT licence.

### Changed
- Keccak-256 comes from pycryptodome (`pycryptodomex`) instead of a hand-written implementation.
  The same test vectors pass.

### Unchanged
- The detectors, the monitor and every number in the README and `docs/evaluation.md`; the bundled
  contracts give the same 23 findings.
