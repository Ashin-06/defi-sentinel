"""Replay a stretch of chain activity through the monitor: ordinary users trading and
borrowing, a sandwich bot, and a flash-loan oracle attack."""
from __future__ import annotations

from dataclasses import dataclass, field

import numpy as np

from .chain import Tx, execute, genesis, oracle_attack
from .monitor import Alert, Monitor, market_value


@dataclass
class Run:
    blocks: list[dict] = field(default_factory=list)
    alerts: list[Alert] = field(default_factory=list)
    attacker_profit: float = 0.0
    market_value_start: float = 0.0
    market_value_end: float = 0.0


def background(rng, n: int) -> list[Tx]:
    txs = []
    for _ in range(n):
        u = f"user{rng.integers(40)}"
        kind = rng.random()
        if kind < 0.6:
            tok = "USDC" if rng.random() < 0.5 else "TKN"
            txs.append(Tx(u, [("swap", "TKN/USDC", tok, float(rng.uniform(100, 8000)))], float(rng.uniform(15, 30)), "swap"))
        elif kind < 0.85:
            txs.append(Tx(u, [("deposit", "lend", float(rng.uniform(1000, 20000)))], float(rng.uniform(15, 30)), "deposit"))
        else:
            txs.append(Tx(u, [("borrow", "lend", float(rng.uniform(100, 3000)))], float(rng.uniform(15, 30)), "borrow"))
    return txs


def run(oracle: str = "spot", guardian: bool = True, blocks: int = 14, seed: int = 0) -> Run:
    rng = np.random.default_rng(seed)
    w = genesis(oracle)
    w.mint("mev-bot", "USDC", 400_000.0)
    mon = Monitor(w, guardian=guardian)
    out = Run(market_value_start=market_value(w, "lend"))
    attacker_start = w.bal("attacker", "USDC")
    for b in range(blocks):
        pending = background(rng, int(rng.integers(4, 9)))
        if b == 5:  # sandwich: bot buys before a whale's buy and sells right after
            pending += [Tx("mev-bot", [("swap", "TKN/USDC", "USDC", 300_000.0)], 60.0, "sandwich front-run"),
                        Tx("user7", [("swap", "TKN/USDC", "USDC", 40_000.0)], 25.0, "large swap"),
                        Tx("mev-bot", [("swap", "TKN/USDC", "TKN", "all")], 10.0, "sandwich back-run")]
        if b == 9:
            pending.append(oracle_attack())
        block_alerts = mon.sandwiches(pending)
        extra = []
        for tx in pending:
            a = mon.inspect(tx)
            if a:
                pause = mon.protect(a, tx)
                if pause:
                    extra.append(pause)
                block_alerts.append(a)
        results = []
        for tx in sorted(pending + extra, key=lambda t: -t.gas_price):
            r = execute(w, tx)
            results.append({"label": tx.label, "sender": tx.sender, "ok": r.ok, "error": r.error})
        w.mine()
        out.alerts += block_alerts
        out.blocks.append({"block": w.block, "price": w.pools["TKN/USDC"].price0(), "twap": w.pools["TKN/USDC"].twap(1800),
                           "market_value": market_value(w, "lend"), "paused": w.markets["lend"].paused,
                           "txs": results, "alerts": [a.kind for a in block_alerts]})
    out.attacker_profit = w.bal("attacker", "USDC") - attacker_start
    out.market_value_end = market_value(w, "lend")
    return out
