"""Score the scanner on SmartBugs Curated: real vulnerable contracts with labelled lines.

SmartBugs Curated (Ferreira et al., ICSE 2020; Apache-2.0): 143 Solidity contracts, most
taken from Etherscan, with 208 vulnerabilities tagged by line and DASP category.
    https://github.com/ASSERT-KTH/smartbugs-curated   (vulnerabilities.json + dataset/)

A labelled vulnerability counts as found when a detector of the matching category reports a
line within LINE_TOLERANCE of it; a contract counts as flagged when any finding of the
matching category is reported in it. File-level checks (compiler version, overflow without
SafeMath) have no line, so they count only at contract level.

    python -m defisentinel smartbugs path/to/smartbugs-curated
"""
from __future__ import annotations

import json
from collections import defaultdict
from pathlib import Path

from .report import scan_path

LINE_TOLERANCE = 3
# detector id -> DASP category it covers
CATEGORY = {
    "reentrancy": "reentrancy",
    "access-control": "access_control", "unprotected-initializer": "access_control",
    "arbitrary-delegatecall": "access_control", "tx-origin": "access_control", "selfdestruct": "access_control",
    "integer-overflow": "arithmetic",
    "weak-randomness": "bad_randomness",
    "timestamp-dependence": "time_manipulation",
    "unchecked-call": "unchecked_low_level_calls", "unchecked-erc20": "unchecked_low_level_calls",
}


def run(root: str | Path) -> dict:
    root = Path(root)
    labels = json.loads((root / "vulnerabilities.json").read_text(encoding="utf-8"))
    per_cat = defaultdict(lambda: {"contracts": 0, "contracts_flagged": 0, "labels": 0, "labels_found": 0})
    line_findings = hits = 0
    for entry in labels:
        findings = next(iter(scan_path(root / entry["path"]).values()))
        mapped = [(CATEGORY[f.id], f.line) for f in findings if f.id in CATEGORY]
        cats = {v["category"] for v in entry["vulnerabilities"]}
        for cat in cats:
            per_cat[cat]["contracts"] += 1
            per_cat[cat]["contracts_flagged"] += any(c == cat for c, _ in mapped)
        labelled_lines = {(v["category"], ln) for v in entry["vulnerabilities"] for ln in v["lines"]}
        for cat, ln in labelled_lines:
            per_cat[cat]["labels"] += 1
            per_cat[cat]["labels_found"] += any(c == cat and line > 1 and abs(line - ln) <= LINE_TOLERANCE for c, line in mapped)
        for _cat, line in mapped:
            if line > 1:  # skip file-level findings
                line_findings += 1
                hits += any(abs(line - ln) <= LINE_TOLERANCE for _, ln in labelled_lines)

    rows = {}
    for cat, r in sorted(per_cat.items()):
        rows[cat] = {**r, "covered_by_a_detector": cat in set(CATEGORY.values()),
                     "contract_recall": round(r["contracts_flagged"] / r["contracts"], 3),
                     "line_recall": round(r["labels_found"] / r["labels"], 3)}
    covered = [r for c, r in rows.items() if r["covered_by_a_detector"]]
    return {
        "dataset": "SmartBugs Curated (143 contracts, 208 labelled vulnerabilities)",
        "contracts": len(labels),
        "line_recall_all": round(sum(r["labels_found"] for r in rows.values()) / sum(r["labels"] for r in rows.values()), 3),
        "line_recall_covered_categories": round(sum(r["labels_found"] for r in covered) / sum(r["labels"] for r in covered), 3),
        "line_findings_on_a_labelled_line": round(hits / max(line_findings, 1), 3),
        "note": ("Contracts can hold real issues that were never labelled, so the last figure is a lower bound on "
                 "precision, not precision itself."),
        "categories": rows,
    }
