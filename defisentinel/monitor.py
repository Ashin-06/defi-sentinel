"""Mempool monitor: simulate every pending transaction on a fork of current state,
flag the ones that break protocol invariants, and (optionally) have a guardian pause
the target market in front of the attack.

Checks per pending transaction
  * value lost by each watched market (collateral marked at TWAP, not spot)
  * in-transaction price deviation of any pool from its TWAP
  * flash-loan funding
  * profit to the sender
Across the pending set
  * sandwiches: same sender trading the same pool right before and after a victim
"""
from __future__ import annotations

from dataclasses import dataclass, field

from .chain import Tx, World, execute


@dataclass
class Alert:
    block: int
    kind: str
    severity: str
    tx_label: str
    sender: str
    summary: str
    details: dict = field(default_factory=dict)
    response: str | None = None
    protected: bool | None = None


def _value(world: World, who: str, ref_pool: str = "TKN/USDC") -> float:
    p = world.pools[ref_pool]
    return world.bal(who, "USDC") + world.bal(who, "TKN") * p.twap(1800)


def market_value(world: World, name: str) -> float:
    """Assets the market can actually recover: cash plus collateral at the TWAP price,
    with every loan capped at the collateral backing it."""
    m = world.markets[name]
    p = world.pools[m.pool].twap(m.twap_window)
    cash = world.bal(m.address, m.debt)
    backed = sum(min(debt, m.deposits.get(u, 0.0) * p) for u, debt in m.borrows.items())
    return cash + backed


class Monitor:
    def __init__(self, world: World, max_deviation: float = 0.25, loss_threshold: float = 25_000.0, guardian: bool = True):
        self.world = world
        self.max_deviation = max_deviation
        self.loss_threshold = loss_threshold
        self.guardian = guardian

    def inspect(self, tx: Tx) -> Alert | None:
        fork = self.world.fork()
        before = {m: market_value(fork, m) for m in fork.markets}
        sender_before = _value(fork, tx.sender)
        r = execute(fork, tx)
        if not r.ok:
            return None
        loss = {m: before[m] - market_value(fork, m) for m in fork.markets}
        worst_market, worst_loss = max(loss.items(), key=lambda kv: kv[1])
        devs = [abs(t["price_after"] - t["twap"]) / t["twap"] for t in r.trace if t["op"] == "swap" and t["twap"] > 0]
        deviation = max(devs, default=0.0)
        flash = any(t["op"] == "flash_borrow" for t in r.trace)
        profit = _value(fork, tx.sender) - sender_before
        details = {"market_loss": round(worst_loss, 2), "market": worst_market, "price_deviation": round(deviation, 4),
                   "flash_loan": flash, "sender_profit": round(profit, 2),
                   "trace": [{k: (round(v, 4) if isinstance(v, float) else v) for k, v in t.items()} for t in r.trace]}
        if worst_loss > self.loss_threshold and (flash or deviation > self.max_deviation):
            return Alert(self.world.block, "oracle-manipulation", "critical", tx.label or "unlabelled", tx.sender,
                         f"would drain ${worst_loss:,.0f} from {worst_market}: pool price pushed {deviation:.0%} off its TWAP"
                         f"{' with a flash loan' if flash else ''}, sender nets ${profit:,.0f}", details)
        if worst_loss > self.loss_threshold:
            return Alert(self.world.block, "protocol-drain", "high", tx.label or "unlabelled", tx.sender,
                         f"would remove ${worst_loss:,.0f} of value from {worst_market}", details)
        if flash and deviation > self.max_deviation:
            return Alert(self.world.block, "price-manipulation", "high", tx.label or "unlabelled", tx.sender,
                         f"flash-loan-funded trade moves a pool {deviation:.0%} away from its TWAP", details)
        return None

    def sandwiches(self, pending: list[Tx]) -> list[Alert]:
        order = sorted(pending, key=lambda t: -t.gas_price)
        swaps = [(i, t, s) for i, t in enumerate(order) for s in t.steps if s[0] == "swap" and len(t.steps) == 1]
        alerts = []
        for vi, victim, vs in swaps:
            for fi, front, fs in swaps:
                if fi >= vi or front.sender == victim.sender or fs[1] != vs[1] or fs[2] != vs[2]:
                    continue
                back = next(((bi, b) for bi, b, bs in swaps if bi > vi and b.sender == front.sender and bs[1] == vs[1] and bs[2] != vs[2]), None)
                if back is None:
                    continue
                with_attack = self.world.fork()
                for t in order[: vi + 1]:
                    if t is front or t is victim or t.sender not in (front.sender, victim.sender):
                        execute(with_attack, t)
                got_with = with_attack.bal(victim.sender, "TKN" if vs[2] == "USDC" else "USDC")
                clean = self.world.fork()
                execute(clean, victim)
                got_without = clean.bal(victim.sender, "TKN" if vs[2] == "USDC" else "USDC")
                loss = got_without - got_with
                if loss > 0:
                    alerts.append(Alert(self.world.block, "sandwich", "medium", victim.label or "swap", front.sender,
                                        f"{front.sender} front-runs and back-runs {victim.sender}'s swap on {vs[1]}; "
                                        f"victim receives {loss:,.2f} fewer {('TKN' if vs[2] == 'USDC' else 'USDC')}",
                                        {"victim": victim.sender, "victim_loss": round(loss, 4), "pool": vs[1]}))
        return alerts

    def protect(self, alert: Alert, attack: Tx) -> Tx | None:
        """Guardian response: pause the target market with a higher gas price, then
        confirm on a fork that the attack now reverts."""
        if not self.guardian or alert.severity != "critical":
            return None
        pause = Tx(self.world.guardian, [("pause", alert.details["market"])], gas_price=attack.gas_price + 5, label="guardian pause")
        fork = self.world.fork()
        execute(fork, pause)
        alert.protected = not execute(fork, attack).ok
        alert.response = f"guardian pauses {alert.details['market']} ahead of the attack (gas {pause.gas_price:.0f} > {attack.gas_price:.0f})"
        return pause
