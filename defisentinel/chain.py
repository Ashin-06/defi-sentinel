"""A small DeFi world that can be forked: a constant-product AMM with a TWAP oracle,
a flash-loan pool, and lending markets that price collateral either from the AMM spot
price (vulnerable) or from the TWAP (safe).

Transactions are programs of steps executed atomically: any revert rolls the world
back, exactly like the EVM. Every step leaves a trace the monitor can inspect.
"""
from __future__ import annotations

import copy
from dataclasses import dataclass, field


class Revert(Exception):
    pass


@dataclass
class Pool:
    name: str
    token0: str
    token1: str
    r0: float
    r1: float
    fee: float = 0.003
    cumulative: float = 0.0  # time-weighted sum of price0 (token1 per token0)
    last_ts: float = 0.0
    history: list = field(default_factory=list)  # (ts, cumulative)

    def price0(self) -> float:
        return self.r1 / self.r0

    def tick(self, ts: float) -> None:
        self.cumulative += self.price0() * (ts - self.last_ts)
        self.last_ts = ts
        self.history.append((ts, self.cumulative))
        self.history = self.history[-500:]

    def twap(self, window: float) -> float:
        if not self.history:
            return self.price0()
        ts_now, cum_now = self.history[-1]
        older = [h for h in self.history if h[0] <= ts_now - window] or self.history[:1]
        t0, c0 = older[-1]
        return (cum_now - c0) / (ts_now - t0) if ts_now > t0 else self.price0()

    def quote(self, token_in: str, amount_in: float) -> float:
        rin, rout = (self.r0, self.r1) if token_in == self.token0 else (self.r1, self.r0)
        a = amount_in * (1 - self.fee)
        return rout * a / (rin + a)


@dataclass
class Lending:
    name: str
    collateral: str
    debt: str
    pool: str
    oracle: str  # "spot" | "twap"
    ltv: float = 0.75
    twap_window: float = 1800.0
    paused: bool = False
    deposits: dict = field(default_factory=dict)
    borrows: dict = field(default_factory=dict)

    @property
    def address(self) -> str:
        return f"protocol:{self.name}"


@dataclass
class World:
    ts: float = 0.0
    block: int = 0
    balances: dict = field(default_factory=dict)  # addr -> token -> amount
    pools: dict = field(default_factory=dict)
    markets: dict = field(default_factory=dict)
    flash_fee: float = 0.0009
    guardian: str = "guardian"

    def fork(self) -> "World":
        return copy.deepcopy(self)

    def bal(self, who: str, token: str) -> float:
        return self.balances.get(who, {}).get(token, 0.0)

    def move(self, token: str, src: str, dst: str, amount: float) -> None:
        if amount < 0 or self.bal(src, token) + 1e-9 < amount:
            raise Revert(f"{src} has insufficient {token}")
        self.balances.setdefault(src, {})[token] = self.bal(src, token) - amount
        self.balances.setdefault(dst, {})[token] = self.bal(dst, token) + amount

    def mint(self, who: str, token: str, amount: float) -> None:
        self.balances.setdefault(who, {})[token] = self.bal(who, token) + amount

    def price(self, market: Lending) -> float:
        p = self.pools[market.pool]
        return p.price0() if market.oracle == "spot" else p.twap(market.twap_window)

    def mine(self, seconds: float = 12.0) -> None:
        self.ts += seconds
        self.block += 1
        for p in self.pools.values():
            p.tick(self.ts)


@dataclass
class Tx:
    sender: str
    steps: list  # ("swap", pool, token_in, amount) | ("deposit", market, amount) | ("borrow", market, amount | "max")
                 # | ("flash", token, amount, [inner steps]) | ("pause", market) | ("repay", market, amount)
    gas_price: float = 20.0
    label: str = ""
    nonce: int = 0


@dataclass
class Receipt:
    ok: bool
    error: str | None
    trace: list


def _run(world: World, tx: Tx, steps: list, trace: list) -> None:
    for st in steps:
        op = st[0]
        if op == "swap":
            _, pname, tin, amount = st
            p = world.pools[pname]
            amount = world.bal(tx.sender, tin) if amount == "all" else amount
            out = p.quote(tin, amount)
            tout = p.token1 if tin == p.token0 else p.token0
            before = p.price0()
            world.move(tin, tx.sender, f"pool:{pname}", amount)
            world.move(tout, f"pool:{pname}", tx.sender, out)
            if tin == p.token0:
                p.r0 += amount
                p.r1 -= out
            else:
                p.r1 += amount
                p.r0 -= out
            trace.append({"op": "swap", "pool": pname, "in": tin, "amount_in": amount, "out": tout, "amount_out": out,
                          "price_before": before, "price_after": p.price0(), "twap": p.twap(1800)})
        elif op == "deposit":
            _, mname, amount = st
            m = world.markets[mname]
            if m.paused:
                raise Revert(f"{mname} is paused")
            amount = world.bal(tx.sender, m.collateral) if amount == "all" else amount
            world.move(m.collateral, tx.sender, m.address, amount)
            m.deposits[tx.sender] = m.deposits.get(tx.sender, 0.0) + amount
            trace.append({"op": "deposit", "market": mname, "amount": amount})
        elif op == "borrow":
            _, mname, amount = st
            m = world.markets[mname]
            if m.paused:
                raise Revert(f"{mname} is paused")
            price = world.price(m)
            limit = m.deposits.get(tx.sender, 0.0) * price * m.ltv - m.borrows.get(tx.sender, 0.0)
            amount = min(limit, world.bal(m.address, m.debt)) if amount == "max" else amount
            if amount > limit + 1e-6:
                raise Revert("undercollateralised")
            world.move(m.debt, m.address, tx.sender, amount)
            m.borrows[tx.sender] = m.borrows.get(tx.sender, 0.0) + amount
            trace.append({"op": "borrow", "market": mname, "amount": amount, "oracle_price": price,
                          "twap": world.pools[m.pool].twap(m.twap_window)})
        elif op == "repay":
            _, mname, amount = st
            m = world.markets[mname]
            world.move(m.debt, tx.sender, m.address, amount)
            m.borrows[tx.sender] = max(0.0, m.borrows.get(tx.sender, 0.0) - amount)
            trace.append({"op": "repay", "market": mname, "amount": amount})
        elif op == "flash":
            _, token, amount, inner = st
            fee = amount * world.flash_fee
            world.move(token, "flashpool", tx.sender, amount)
            trace.append({"op": "flash_borrow", "token": token, "amount": amount})
            _run(world, tx, inner, trace)
            world.move(token, tx.sender, "flashpool", amount + fee)
            trace.append({"op": "flash_repay", "token": token, "amount": amount + fee})
        elif op == "pause":
            if tx.sender != world.guardian:
                raise Revert("only guardian")
            world.markets[st[1]].paused = True
            trace.append({"op": "pause", "market": st[1]})
        else:
            raise Revert(f"unknown op {op}")


def execute(world: World, tx: Tx) -> Receipt:
    """Apply tx atomically. On revert the world is unchanged."""
    snap = copy.deepcopy((world.balances, world.pools, world.markets))
    trace: list = []
    try:
        _run(world, tx, tx.steps, trace)
        return Receipt(True, None, trace)
    except Revert as e:
        world.balances, world.pools, world.markets = snap
        return Receipt(False, str(e), trace)


def genesis(oracle: str = "spot") -> World:
    w = World()
    w.pools["TKN/USDC"] = Pool("TKN/USDC", "TKN", "USDC", 1_000_000.0, 1_000_000.0)
    w.mint("pool:TKN/USDC", "TKN", 1_000_000.0)
    w.mint("pool:TKN/USDC", "USDC", 1_000_000.0)
    w.markets["lend"] = Lending("lend", "TKN", "USDC", "TKN/USDC", oracle)
    w.mint("protocol:lend", "USDC", 5_000_000.0)
    w.mint("flashpool", "USDC", 50_000_000.0)
    for i in range(40):
        w.mint(f"user{i}", "USDC", 50_000.0)
        w.mint(f"user{i}", "TKN", 50_000.0)
    w.mint("attacker", "USDC", 1_000.0)  # gas money only
    for _ in range(200):  # history for the TWAP
        w.mine()
    return w


def oracle_attack(amount: float = 2_000_000.0) -> Tx:
    return Tx("attacker", [("flash", "USDC", amount, [
        ("swap", "TKN/USDC", "USDC", amount),
        ("deposit", "lend", "all"),
        ("borrow", "lend", "max"),
    ])], gas_price=40.0, label="flash-loan oracle manipulation")
