"""The scanning API: settings, auth, limits, headers, metrics, health, scan history and migrations."""
import hashlib
import importlib
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import text

from defisentinel import db, ops

ROOT = Path(__file__).resolve().parent.parent
VULN = (ROOT / "contracts" / "VulnerableVault.sol").read_text(encoding="utf-8")
SAFE = (ROOT / "contracts" / "SafeLending.sol").read_text(encoding="utf-8")
KEY = "defisentinel_" + "x" * 40
HASHED = {f"sha256:{hashlib.sha256(KEY.encode()).hexdigest()}": {"user": "ci", "role": "scanner"}}


def boot(monkeypatch, **env):
    for k in [k for k in os.environ if k.startswith("DEFISENTINEL_")]:
        monkeypatch.delenv(k)
    for k, v in env.items():
        monkeypatch.setenv(f"DEFISENTINEL_{k}", v)
    import defisentinel.api as api

    return importlib.reload(api)


@pytest.mark.parametrize("change, message", [
    ({"DEFISENTINEL_API_KEYS": None}, "API keys"),
    ({"DEFISENTINEL_DATABASE_URL": None}, "DATABASE_URL"),
    ({"DEFISENTINEL_API_KEYS": json.dumps({KEY: {"user": "ci", "role": "scanner"}})}, "sha256"),
    ({"DEFISENTINEL_API_KEYS": json.dumps({"sha256:" + "0" * 64: {"user": "x", "role": "root"}})}, "roles"),
    ({"DEFISENTINEL_CORS_ORIGINS": "*"}, "CORS"),
])
def test_production_settings_refused(change, message):
    env = {"DEFISENTINEL_ENV": "production", "DEFISENTINEL_API_KEYS": json.dumps(HASHED),
           "DEFISENTINEL_DATABASE_URL": "sqlite://"}
    assert ops.load_settings(env).production
    env.update(change)
    with pytest.raises(ops.ConfigError, match=message):
        ops.load_settings({k: v for k, v in env.items() if v is not None})


def test_no_public_bind_and_readable_exit():
    with pytest.raises(ops.ConfigError, match="without API keys"):
        ops.load_settings({"DEFISENTINEL_HOST": "0.0.0.0"})
    env = {k: v for k, v in os.environ.items() if not k.startswith("DEFISENTINEL_")}
    r = subprocess.run([sys.executable, "-m", "defisentinel", "serve", "--host", "0.0.0.0"], env=env,
                       capture_output=True, text=True, timeout=120, check=False)
    assert r.returncode != 0 and "without API keys" in r.stderr


def test_scan_gates_and_is_recorded_across_a_restart(monkeypatch, tmp_path):
    url = os.environ.get("TEST_DATABASE_URL") or f"sqlite:///{tmp_path / 'scans.db'}"
    c = TestClient(boot(monkeypatch, DATABASE_URL=url).app)
    bad = c.post("/v1/scan", json={"files": {"VulnerableVault.sol": VULN}, "fail_on": "high", "label": "repo@abc123"}).json()
    good = c.post("/v1/scan", json={"files": {"SafeLending.sol": SAFE}, "fail_on": "high"}).json()
    assert bad["passed"] is False and bad["summary"]["critical"] + bad["summary"]["high"] > 0
    assert good["passed"] is True
    sarif = c.post("/v1/scan", json={"files": {"VulnerableVault.sol": VULN}, "format": "sarif"}).json()["report"]
    assert sarif["version"] == "2.1.0"

    c = TestClient(boot(monkeypatch, DATABASE_URL=url).app)  # restart
    got = c.get(f"/v1/scans/{bad['scan_id']}").json()
    assert got["label"] == "repo@abc123" and got["passed"] is False and got["fail_on"] == "high"
    assert got["files"]["VulnerableVault.sol"] == hashlib.sha256(VULN.encode()).hexdigest()
    assert "function" not in json.dumps(got["files"])  # sources are not stored
    assert got["findings"]["VulnerableVault.sol"]
    assert any(s["id"] == good["scan_id"] for s in c.get("/v1/scans").json()["scans"])
    assert c.get("/v1/scans/nope").status_code == 404


def test_roles_and_metrics(monkeypatch):
    keys = {"k-ci": {"user": "ci", "role": "scanner"}, "k-view": {"user": "vic", "role": "viewer"},
            "k-mon": {"user": "prom", "role": "monitor"}}
    c = TestClient(boot(monkeypatch, API_KEYS=json.dumps(keys)).app)
    body = {"files": {"VulnerableVault.sol": VULN}}
    assert c.post("/v1/scan", json=body).status_code == 401
    assert c.post("/v1/scan", json=body, headers={"x-api-key": "k-view"}).status_code == 403
    assert c.post("/v1/scan", json=body, headers={"x-api-key": "k-ci"}).status_code == 200
    assert c.get("/v1/scans", headers={"authorization": "Bearer k-view"}).status_code == 200
    assert c.get("/metrics", headers={"x-api-key": "k-ci"}).status_code == 403
    m = c.get("/metrics", headers={"x-api-key": "k-mon"})
    assert m.status_code == 200 and 'defisentinel_decisions_total{decision="scan_passed"}' in m.text


def test_limits_headers_errors_and_health(monkeypatch):
    c = TestClient(boot(monkeypatch, RATE_LIMIT="3").app)
    codes = [c.get("/v1/scans").status_code for _ in range(5)]
    assert codes[:3] == [200] * 3 and codes[3:] == [429, 429]
    api = boot(monkeypatch, MAX_BODY_BYTES="500")

    @api.app.get("/boom")
    def boom():
        raise RuntimeError("secret detail: private key 0xdeadbeef")

    c = TestClient(api.app)
    assert c.post("/v1/scan", json={"files": {"a.sol": "x" * 600}}).status_code == 413

    def chunks():
        for _ in range(10):
            yield b"a" * 100

    assert c.post("/v1/scan", content=chunks(), headers={"content-type": "application/json"}).status_code == 413
    crash = c.get("/boom")
    assert crash.status_code == 500 and "deadbeef" not in crash.text and crash.json()["request_id"]
    bad = c.post("/v1/scan", json={"files": {"a.sol": ["contract SECRET {}"]}})
    assert bad.status_code == 422 and "SECRET" not in bad.text
    r = c.get("/v1/scans", headers={"x-request-id": "abc-123"})
    assert r.headers["x-request-id"] == "abc-123" and r.headers["content-security-policy"] == ops.API_CSP
    assert c.get("/healthz").json() == {"status": "ok"}
    assert c.get("/readyz").json()["checks"] == {"database": True}
    monkeypatch.setattr(api.engine, "connect", lambda: (_ for _ in ()).throw(RuntimeError("db down")))
    assert c.get("/readyz").status_code == 503


def test_json_logs_carry_request_ids(capsys):
    ops.setup_logging("INFO")
    token = ops.request_id.set("rid-1")
    ops.log.info("hello")
    ops.request_id.reset(token)
    assert json.loads(capsys.readouterr().out.strip().splitlines()[-1])["request_id"] == "rid-1"


def test_migrations_apply_once(tmp_path):
    url = f"sqlite:///{tmp_path / 'm.db'}"
    eng = db.engine(url)
    assert db.migrate(eng) == ["001_init.sql"] and db.migrate(eng) == []
    with eng.connect() as c:
        tables = {r[0] for r in c.execute(text("SELECT name FROM sqlite_master WHERE type = 'table'"))}
    assert {"scans", "schema_migrations"} <= tables
    env = {**{k: v for k, v in os.environ.items() if not k.startswith("DEFISENTINEL_")}, "DEFISENTINEL_DATABASE_URL": url}
    out = subprocess.run([sys.executable, "-m", "defisentinel", "migrate"], env=env, capture_output=True, text=True,
                         timeout=120, check=False)
    assert out.returncode == 0 and "up to date" in out.stdout
