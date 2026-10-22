"""Scan files/directories and render findings as text, Markdown or SARIF 2.1.0
(for GitHub code scanning and most CI security dashboards)."""
from __future__ import annotations

import json
from pathlib import Path

from .detectors import SEVERITY_ORDER, Finding, unit_findings
from .solidity import parse

SARIF_LEVEL = {"critical": "error", "high": "error", "medium": "warning", "low": "note", "info": "note"}


def scan_path(path: str | Path) -> dict[str, list[Finding]]:
    p = Path(path)
    files = sorted(p.rglob("*.sol")) if p.is_dir() else [p]
    out = {}
    for f in files:
        if "node_modules" in f.parts or "lib" in f.parts and "openzeppelin" in str(f).lower():
            continue
        out[str(f)] = unit_findings(parse(f.read_text(encoding="utf-8", errors="replace"), str(f)))
    return out


def summary(results: dict[str, list[Finding]]) -> dict[str, int]:
    counts = {s: 0 for s in SEVERITY_ORDER}
    for fs in results.values():
        for f in fs:
            counts[f.severity] += 1
    return counts


def markdown(results: dict[str, list[Finding]]) -> str:
    c = summary(results)
    lines = ["# Smart contract scan", "", " · ".join(f"**{v}** {k}" for k, v in c.items() if v) or "No findings.", ""]
    for path, fs in results.items():
        if not fs:
            continue
        lines += [f"## {path}", ""]
        for f in fs:
            where = f"{f.contract}.{f.function}" if f.function else f.contract
            lines += [f"### [{f.severity.upper()}] {f.title}", f"`{where}` line {f.line}", "", f"```solidity\n{f.snippet}\n```", "",
                      f.detail, "", f"**Fix:** {f.fix}", ""]
    return "\n".join(lines)


def sarif(results: dict[str, list[Finding]]) -> dict:
    rules, seen = [], set()
    res = []
    for path, fs in results.items():
        for f in fs:
            if f.id not in seen:
                seen.add(f.id)
                rules.append({"id": f.id, "name": f.title, "shortDescription": {"text": f.title}, "help": {"text": f.fix},
                              "properties": {"security-severity": {"critical": "9.5", "high": "8.0", "medium": "5.5", "low": "3.0", "info": "1.0"}[f.severity]}})
            res.append({"ruleId": f.id, "level": SARIF_LEVEL[f.severity], "message": {"text": f.detail},
                        "locations": [{"physicalLocation": {"artifactLocation": {"uri": Path(path).as_posix()},
                                                            "region": {"startLine": f.line}}}]})
    return {"$schema": "https://json.schemastore.org/sarif-2.1.0.json", "version": "2.1.0",
            "runs": [{"tool": {"driver": {"name": "defi-sentinel", "version": "1.0.0", "rules": rules}}, "results": res}]}


def plain_text(results: dict[str, list[Finding]]) -> str:
    lines = []
    for path, fs in results.items():
        for f in fs:
            where = f"{f.contract}.{f.function}" if f.function else f.contract
            lines.append(f"{path}:{f.line}  [{f.severity.upper():8s}] {f.title}  ({where})")
            lines.append(f"    {f.snippet}")
    lines.append("\n" + "  ".join(f"{k}: {v}" for k, v in summary(results).items()))
    return "\n".join(lines)


def write(results, fmt: str, out: str | None) -> str:
    if fmt == "text":
        text = plain_text(results)
    elif fmt in ("md", "markdown"):
        text = markdown(results)
    elif fmt == "sarif":
        text = json.dumps(sarif(results), indent=2)
    else:
        text = json.dumps({k: [f.as_dict() for f in v] for k, v in results.items()}, indent=2)
    if out:
        Path(out).write_text(text, encoding="utf-8")
    return text
