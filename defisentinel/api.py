"""Scanning service: the static analyser behind an API, with a stored history of scans.

    POST /v1/scan             scan Solidity sources; returns findings, a summary and pass/fail [scan]
    GET  /v1/scans[/{id}]     past scans [read]
    GET  /healthz, /readyz, /metrics

Sources are scanned in memory and not stored; each scan keeps the SHA-256 of every file, the
findings and who asked. Callers send an API key whose role decides the permissions in brackets;
settings come from DEFISENTINEL_* variables (see ops.py and docs/runbook.md).

    python -m defisentinel serve
"""
from __future__ import annotations

import hashlib
import json
import threading
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, Optional

from fastapi import Depends, FastAPI, HTTPException, Query
from pydantic import BaseModel, Field
from sqlalchemy import text

from . import db, ops
from .detectors import SEVERITY_ORDER, unit_findings
from .report import sarif, summary
from .solidity import parse

settings = ops.load_settings()
ops.setup_logging(settings.log_level)
engine = db.connect(settings.database_url)
_lock = threading.Lock()

app = FastAPI(title="DeFi Sentinel scanning service", version="1.0.0")
ops.install(app, settings, {"database": lambda: engine.connect().close()})

MAX_FILES = 200


class ScanRequest(BaseModel):
    files: Dict[str, str] = Field(..., min_length=1, max_length=MAX_FILES,
                                  description="file name -> Solidity source")
    label: str = Field("", max_length=200, description="e.g. a repository and commit, for the history")
    fail_on: Optional[str] = Field(None, pattern="^(critical|high|medium|low|info)$",
                                   description="fail the scan if a finding at or above this severity exists")
    format: str = Field("json", pattern="^(json|sarif)$")


@app.post("/v1/scan")
def scan(req: ScanRequest, ident: dict = Depends(ops.require("scan"))) -> Dict[str, Any]:
    if any(len(name) > 300 for name in req.files):
        raise HTTPException(422, "file names may be at most 300 characters")
    results = {name: unit_findings(parse(src, name)) for name, src in sorted(req.files.items())}
    counts = summary(results)
    limit = SEVERITY_ORDER.get(req.fail_on) if req.fail_on else None
    passed = limit is None or not any(SEVERITY_ORDER[f.severity] <= limit for fs in results.values() for f in fs)
    findings = {name: [f.as_dict() for f in fs] for name, fs in results.items()}
    for fs in results.values():
        for f in fs:
            ops.DECISIONS.labels(decision=f.severity).inc()
    ops.DECISIONS.labels(decision="scan_passed" if passed else "scan_failed").inc()
    hashes = {name: hashlib.sha256(src.encode()).hexdigest() for name, src in req.files.items()}
    sid = uuid.uuid4().hex
    with _lock, engine.begin() as c:
        c.execute(text("INSERT INTO scans VALUES (:i, :t, :u, :l, :p, :f, :s, :fl, :fd)"),
                  {"i": sid, "t": datetime.now(timezone.utc).isoformat(timespec="microseconds"),
                   "u": ident["user"] or "demo", "l": req.label, "p": int(passed), "f": req.fail_on,
                   "s": json.dumps(counts), "fl": json.dumps(hashes), "fd": json.dumps(findings)})
    out: Dict[str, Any] = {"scan_id": sid, "passed": passed, "summary": counts}
    out["report"] = sarif(results) if req.format == "sarif" else findings
    return out


def _row(r) -> Dict[str, Any]:
    d = dict(r)
    d["passed"] = bool(d["passed"])
    for k in ("summary", "files", "findings"):
        if k in d:
            d[k] = json.loads(d[k])
    return d


@app.get("/v1/scans", dependencies=[Depends(ops.require("read"))])
def list_scans(limit: int = Query(50, ge=1, le=1000)) -> Dict[str, Any]:
    with engine.connect() as c:
        rows = c.execute(text("SELECT id, created_at, requested_by, label, passed, fail_on, summary FROM scans "
                              "ORDER BY created_at DESC LIMIT :n"), {"n": limit}).mappings().all()
    return {"scans": [_row(r) for r in rows]}


@app.get("/v1/scans/{scan_id}", dependencies=[Depends(ops.require("read"))])
def get_scan(scan_id: str) -> Dict[str, Any]:
    with engine.connect() as c:
        r = c.execute(text("SELECT * FROM scans WHERE id = :i"), {"i": scan_id[:64]}).mappings().first()
    if r is None:
        raise HTTPException(404, "scan not found")
    return _row(r)
