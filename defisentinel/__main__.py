"""Command line.

    python -m defisentinel scan contracts/ [--format text|md|sarif|json] [--out report.sarif] [--fail-on high]
    python -m defisentinel simulate [--oracle spot|twap] [--no-guardian]
    python -m defisentinel watch --rpc https://... --contract 0xYourPool [--contract ...]
"""
from __future__ import annotations

import argparse
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
    w = sub.add_parser("watch", help="watch a live chain over JSON-RPC")
    w.add_argument("--rpc", required=True)
    w.add_argument("--contract", action="append", default=[])
    w.add_argument("--interval", type=float, default=2.0)
    a = ap.parse_args(argv)

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
