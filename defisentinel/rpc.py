"""Watch a live EVM chain over JSON-RPC.

Polls the pending block (or latest, if the provider hides the mempool), decodes
function selectors, and alerts on flash-loan transactions that touch the contracts you
protect. When the node supports `debug_traceCall`, the call tree is used to find
watched contracts reached indirectly (the usual case: attack contract -> flash loan ->
your protocol).
"""
from __future__ import annotations

import time
from dataclasses import dataclass

import httpx

from .keccak import selector

SIGNATURES = {
    "flashLoan(address,address[],uint256[],uint256[],address,bytes,uint16)": ("Aave V3 flashLoan", True),
    "flashLoanSimple(address,address,uint256,bytes,uint16)": ("Aave V3 flashLoanSimple", True),
    "flashLoan(address,address[],uint256[],bytes)": ("Balancer flashLoan", True),
    "flash(address,uint256,uint256,bytes)": ("Uniswap V3 flash", True),
    "flashLoan(address,address,uint256,bytes)": ("ERC-3156 flashLoan", True),
    "swap(uint256,uint256,address,bytes)": ("Uniswap V2 swap (flash swap when data set)", False),
    "transfer(address,uint256)": ("ERC20 transfer", False),
    "approve(address,uint256)": ("ERC20 approve", False),
}
KNOWN = {selector(sig): (name, flash) for sig, (name, flash) in SIGNATURES.items()}


@dataclass
class ChainAlert:
    tx_hash: str
    sender: str
    to: str
    reason: str
    method: str


class Client:
    def __init__(self, url: str, transport: httpx.BaseTransport | None = None, timeout: float = 10.0):
        self.http = httpx.Client(transport=transport, timeout=timeout)
        self.url = url
        self._id = 0

    def call(self, method: str, params: list):
        self._id += 1
        r = self.http.post(self.url, json={"jsonrpc": "2.0", "id": self._id, "method": method, "params": params})
        r.raise_for_status()
        body = r.json()
        if "error" in body:
            raise RuntimeError(f"{method}: {body['error'].get('message')}")
        return body["result"]


def _walk(frame: dict):
    yield frame
    for c in frame.get("calls", []) or []:
        yield from _walk(c)


def analyse_tx(client: Client, tx: dict, watched: set[str], use_trace: bool = True) -> ChainAlert | None:
    data = (tx.get("input") or "0x")[:10].lower()
    method, is_flash = KNOWN.get(data, ("unknown", False))
    to = (tx.get("to") or "").lower()
    touched = {to}
    if use_trace and watched:
        try:
            frame = client.call("debug_traceCall", [{k: tx[k] for k in ("from", "to", "input", "value", "gas") if tx.get(k)},
                                                    "latest", {"tracer": "callTracer"}])
            for f in _walk(frame):
                touched.add((f.get("to") or "").lower())
                if (f.get("input") or "")[:10].lower() in KNOWN and KNOWN[(f.get("input") or "")[:10].lower()][1]:
                    is_flash, method = True, KNOWN[f["input"][:10].lower()][0]
        except (RuntimeError, httpx.HTTPError):
            pass  # provider without debug namespace: fall back to top-level decoding
    hits = touched & watched
    if is_flash and (hits or not watched):
        return ChainAlert(tx["hash"], tx.get("from", ""), to, f"flash loan ({method})" + (f" reaching watched {', '.join(sorted(hits))}" if hits else ""), method)
    if hits and to not in watched:
        return ChainAlert(tx["hash"], tx.get("from", ""), to, f"contract call reaching watched {', '.join(sorted(hits))} indirectly", method)
    return None


def watch(url: str, watched: list[str], interval: float = 2.0, rounds: int | None = None, on_alert=print,
          transport: httpx.BaseTransport | None = None) -> list[ChainAlert]:
    client = Client(url, transport)
    watched_set = {w.lower() for w in watched}
    seen, alerts, n = set(), [], 0
    while rounds is None or n < rounds:
        n += 1
        try:
            block = client.call("eth_getBlockByNumber", ["pending", True]) or client.call("eth_getBlockByNumber", ["latest", True])
        except (RuntimeError, httpx.HTTPError):
            block = client.call("eth_getBlockByNumber", ["latest", True])
        for tx in (block or {}).get("transactions", []):
            if tx["hash"] in seen:
                continue
            seen.add(tx["hash"])
            a = analyse_tx(client, tx, watched_set)
            if a:
                alerts.append(a)
                on_alert(a)
        if rounds is None or n < rounds:
            time.sleep(interval)
    return alerts
