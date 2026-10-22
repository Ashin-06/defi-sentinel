"""Lightweight Solidity source model: contracts, functions, modifiers and state
variables with line numbers. No compiler needed, so it works on single files, partial
code and code that does not compile yet (audits in progress, snippets from incidents)."""
from __future__ import annotations

import re
from dataclasses import dataclass, field

VISIBILITY = {"public", "external", "internal", "private"}
MUTABILITY = {"view", "pure", "payable", "nonpayable"}
KEYWORDS = VISIBILITY | MUTABILITY | {"virtual", "override", "returns", "constant", "immutable"}


def strip_comments_and_strings(src: str) -> str:
    """Blank out comments and string literals but keep offsets and newlines, so line
    numbers stay correct and braces inside strings do not confuse matching."""
    out, i, n = [], 0, len(src)
    while i < n:
        c = src[i]
        if src.startswith("//", i):
            j = src.find("\n", i)
            j = n if j < 0 else j
            out.append(" " * (j - i))
            i = j
        elif src.startswith("/*", i):
            j = src.find("*/", i + 2)
            j = n if j < 0 else j + 2
            out.append("".join(ch if ch == "\n" else " " for ch in src[i:j]))
            i = j
        elif c in "\"'":
            j = i + 1
            while j < n and src[j] != c:
                j += 2 if src[j] == "\\" else 1
            out.append(c + " " * (min(j, n) - i - 1) + (c if j < n else ""))
            i = j + 1
        else:
            out.append(c)
            i += 1
    return "".join(out)


def match_brace(s: str, open_idx: int) -> int:
    depth = 0
    for k in range(open_idx, len(s)):
        if s[k] == "{":
            depth += 1
        elif s[k] == "}":
            depth -= 1
            if depth == 0:
                return k
    return len(s) - 1


@dataclass
class Function:
    name: str
    kind: str  # function | constructor | receive | fallback | modifier
    params: list[str]
    visibility: str
    mutability: str
    modifiers: list[str]
    body: str
    start_line: int
    body_offset: int  # absolute offset of the body's '{' in the cleaned source

    @property
    def mutates(self) -> bool:
        return self.mutability not in ("view", "pure")

    @property
    def exposed(self) -> bool:
        return self.visibility in ("public", "external") or self.kind in ("receive", "fallback")


@dataclass
class Contract:
    name: str
    kind: str  # contract | interface | library | abstract
    bases: list[str]
    start_line: int
    state_vars: dict[str, str] = field(default_factory=dict)  # name -> type
    functions: list[Function] = field(default_factory=list)
    modifiers: dict[str, Function] = field(default_factory=dict)


@dataclass
class SourceUnit:
    path: str
    raw: str
    clean: str
    pragma: str | None
    contracts: list[Contract]

    def line_of(self, offset: int) -> int:
        return self.raw.count("\n", 0, offset) + 1

    def line_text(self, line: int) -> str:
        lines = self.raw.splitlines()
        return lines[line - 1].strip() if 0 < line <= len(lines) else ""


CONTRACT_RE = re.compile(r"\b(abstract\s+contract|contract|interface|library)\s+(\w+)(?:\s+is\s+([^{]+))?\s*\{")
FUNC_RE = re.compile(r"\b(function\s+(\w+)|constructor|receive|fallback|modifier\s+(\w+))\s*\(([^)]*)\)([^{;]*)([{;])")
STATE_RE = re.compile(r"^\s*((?:mapping\s*\(.+?\)|[A-Za-z_]\w*(?:\[\])*)(?:\s+(?:public|private|internal|constant|immutable|override))*)\s+(\w+)\s*(?:=[^;]*)?;", re.M)


def parse(src: str, path: str = "<source>") -> SourceUnit:
    clean = strip_comments_and_strings(src)
    pm = re.search(r"pragma\s+solidity\s+([^;]+);", src)
    unit = SourceUnit(path, src, clean, pm.group(1).strip() if pm else None, [])
    for m in CONTRACT_RE.finditer(clean):
        open_idx = m.end() - 1
        close = match_brace(clean, open_idx)
        kind = "abstract" if m.group(1).startswith("abstract") else m.group(1)
        c = Contract(m.group(2), kind, [b.strip().split("(")[0] for b in (m.group(3) or "").split(",") if b.strip()], unit.line_of(m.start()))
        body = clean[open_idx + 1 : close]
        base = open_idx + 1
        spans = []
        for fm in FUNC_RE.finditer(body):
            head = fm.group(1)
            kindf = "modifier" if head.startswith("modifier") else ("function" if head.startswith("function") else head)
            name = fm.group(2) or fm.group(3) or head
            attrs = fm.group(5)
            words = re.findall(r"[A-Za-z_]\w*", re.sub(r"returns\s*\([^)]*\)", "", attrs))
            vis = next((w for w in words if w in VISIBILITY), "public" if kindf in ("constructor", "modifier") else "internal" if kindf == "function" else "external")
            mut = next((w for w in words if w in MUTABILITY), "nonpayable")
            mods = [w for w in words if w not in KEYWORDS]
            if fm.group(6) == "{":
                b_open = fm.end() - 1
                b_close = match_brace(body, b_open)
                fbody = body[b_open + 1 : b_close]
                spans.append((fm.start(), b_close))
            else:
                b_open, fbody = fm.end() - 1, ""
                spans.append((fm.start(), fm.end()))
            f = Function(name, kindf, [p.strip() for p in fm.group(4).split(",") if p.strip()], vis, mut, mods, fbody,
                         unit.line_of(base + fm.start()), base + b_open)
            (c.modifiers.__setitem__(name, f) if kindf == "modifier" else c.functions.append(f))
        # state variables: declarations outside any function span
        outside = list(body)
        for s, e in spans:
            outside[s : e + 1] = " " * (e + 1 - s)
        for sm in STATE_RE.finditer("".join(outside)):
            typ, name = sm.group(1), sm.group(2)
            if name not in ("return",) and not typ.startswith(("event", "error", "using", "emit", "struct")):
                c.state_vars[name] = typ.split()[0]
        unit.contracts.append(c)
    return unit
