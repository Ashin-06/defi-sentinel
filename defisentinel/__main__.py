"""Command line.

    python -m defisentinel scan contracts/ [--format text|md|sarif|json] [--out report.sarif] [--fail-on high]
    python -m defisentinel simulate [--oracle spot|twap] [--no-guardian]
    python -m defisentinel watch --rpc https://... --contract 0xYourPool [--contract ...]
    python -m defisentinel serve        # scanning API (settings: DEFISENTINEL_* environment variables)
    python -m defisentinel migrate      # apply database migrations and exit
"""
from __future__ import annotations

import argparse
import os
import sys

from .detectors import SEVERITY_ORDER
from .report import scan_path, summary, write


def main(argv=None):
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")
    ap = argparse.ArgumentParser(prog="defisentinel")
    sub = ap.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("scan", help="static analysis of Solidity files")
    s.add_argument("path")
    s.add_argument("--format", choices=["text", "md", "sarif", "json"], default="text")
    s.add_argument("--out")
    s.add_argument("--fail-on", choices=list(SEVERITY_ORDER), help="exit 1 if a finding at or above this severity exists (CI)")
    m = sub.add_parser("simulate", help="mempool monitor on a simulated chain")
    m.add_argument("--oracle", choices=["spot", "twap"], default="spot")
    m.add_argument("--no-guardian", action="store_true")
    b = sub.add_parser("smartbugs", help="score the scanner on the SmartBugs Curated labelled contracts")
    b.add_argument("path", help="checkout of github.com/ASSERT-KTH/smartbugs-curated")
    b.add_argument("--out", default="smartbugs_results.json")
    w = sub.add_parser("watch", help="watch a live chain over JSON-RPC")
    w.add_argument("--rpc", required=True)
    w.add_argument("--contract", action="append", default=[])
    w.add_argument("--interval", type=float, default=2.0)
    sv = sub.add_parser("serve", help="scanning API")
    sv.add_argument("--host", help="default DEFISENTINEL_HOST or 127.0.0.1; any other address needs API keys")
    sv.add_argument("--port", type=int, help="default DEFISENTINEL_PORT or 8008")
    sub.add_parser("migrate", help="apply database migrations to DEFISENTINEL_DATABASE_URL")
    a = ap.parse_args(argv)

    if a.cmd in ("serve", "migrate"):
        from . import db, ops

        for name, val in (("HOST", getattr(a, "host", None)), ("PORT", getattr(a, "port", None))):
            if val is not None:
                os.environ[f"DEFISENTINEL_{name}"] = str(val)
        try:
            settings = ops.load_settings()  # fail here, before uvicorn, with a readable message
        except ops.ConfigError as e:
            sys.exit(f"configuration error: {e}")
        if a.cmd == "migrate":
            print(*(db.migrate(db.engine(settings.database_url)) or ["up to date"]), sep="\n")
            return
        import uvicorn

        ops.setup_logging(settings.log_level)
        uvicorn.run("defisentinel.api:app", host=settings.host, port=settings.port, log_config=None, access_log=False)
        return

    if a.cmd == "smartbugs":
        import json
        from pathlib import Path

        from .benchmark import run

        res = run(a.path)
        for cat, r in res["categories"].items():
            print(f"{cat:28s} contracts {r['contracts_flagged']:>2}/{r['contracts']:<2}  labelled lines {r['labels_found']:>2}/{r['labels']}")
        print(f"line recall {res['line_recall_all']:.1%} overall, {res['line_recall_covered_categories']:.1%} in covered categories")
        Path(a.out).parent.mkdir(parents=True, exist_ok=True)
        Path(a.out).write_text(json.dumps(res, indent=2))
        return
    if a.cmd == "scan":
        res = scan_path(a.path)
        if a.format == "text":
            for path, fs in res.items():
                for f in fs:
                    where = f"{f.contract}.{f.function}" if f.function else f.contract
                    print(f"{path}:{f.line}  [{f.severity.upper():8s}] {f.title}  ({where})")
                    print(f"    {f.snippet}")
            print("\n" + "  ".join(f"{k}: {v}" for k, v in summary(res).items()))
            if a.out:
                write(res, "text", a.out)
        else:
            text = write(res, a.format, a.out)
            if not a.out:
                print(text)
        if a.fail_on:
            limit = SEVERITY_ORDER[a.fail_on]
            if any(SEVERITY_ORDER[f.severity] <= limit for fs in res.values() for f in fs):
                sys.exit(1)
    elif a.cmd == "simulate":
        from .scenario import run

        r = run(a.oracle, not a.no_guardian)
        for b in r.blocks:
            flags = f"  ALERTS: {', '.join(b['alerts'])}" if b["alerts"] else ""
            print(f"block {b['block']}  price {b['price']:.3f}  twap {b['twap']:.3f}  market ${b['market_value']:,.0f}"
                  f"{'  [PAUSED]' if b['paused'] else ''}{flags}")
        print()
        for al in r.alerts:
            print(f"[{al.severity.upper()}] {al.kind}: {al.summary}")
            if al.response:
                print(f"    response: {al.response} -> {'attack reverted' if al.protected else 'NOT stopped'}")
        print(f"\nattacker profit ${r.attacker_profit:,.0f}; market value ${r.market_value_start:,.0f} -> ${r.market_value_end:,.0f}")
    else:
        from .rpc import watch

        watch(a.rpc, a.contract, a.interval, on_alert=lambda x: print(f"[ALERT] {x.tx_hash} from {x.sender}: {x.reason}"))


if __name__ == "__main__":
    main()
