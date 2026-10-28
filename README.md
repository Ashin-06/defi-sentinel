# DeFi Sentinel

Two layers of protection for DeFi protocols:

1. Before deployment, a Solidity scanner for the bug classes behind the largest DeFi losses. Each finding explains how the bug gets exploited, and results can go to CI as SARIF.
2. After deployment, a mempool monitor that simulates each pending transaction on a copy of current state. It catches flash-loan price manipulation and sandwich attacks before they are confirmed, and can have a guardian pause the market first.

## Contract scanner

```
$ python -m defisentinel scan contracts/VulnerableLending.sol
contracts/VulnerableLending.sol:37  [CRITICAL] Price read from a manipulable spot source  (VulnerableLending.collateralPrice)
    (uint112 r0, uint112 r1, ) = pair.getReserves();
contracts/VulnerableLending.sol:59  [CRITICAL] State updated after external call (re-entrancy)  (VulnerableLending.withdrawEth)
    (bool ok, ) = msg.sender.call{value: amount}("");
contracts/VulnerableLending.sol:64  [CRITICAL] `setPriceFeed` is callable by anyone  (VulnerableLending.setPriceFeed)
...
```

| Detector | Known incidents of this kind |
|---|---|
| `spot-price-oracle`: price taken from pool reserves or balances | bZx, Harvest, Inverse, Mango |
| `reentrancy`: state written after an external call, with no guard | The DAO, Cream, Fei/Rari |
| `access-control`: sensitive function with no owner or role check | Poly Network, many `mint` bugs |
| `unprotected-initializer`: `initialize` without an initializer guard | Parity wallet, Wormhole |
| `arbitrary-delegatecall`: delegatecall to an address the caller chooses | Parity, Furucombo |
| `tx-origin`: authorisation through `tx.origin` | phishing takeovers |
| `share-inflation`: 1:1 shares on an empty vault | ERC4626 first-depositor attacks |
| `msg-value-in-loop`: `msg.value` counted on every loop iteration | Opyn, SushiSwap MISO |
| `signature-replay`: `ecrecover` without a nonce or deadline | cross-chain replays |
| `weak-randomness` and `timestamp-dependence`: block data used for randomness or decisions | on-chain lotteries |
| `unchecked-call` / `unchecked-erc20`: ignored success flags | tokens that return false |
| `integer-overflow`, `divide-before-multiply`, `selfdestruct`, `floating-pragma` | BEC token |

The scanner has its own Solidity source model, so it needs no compiler and works on single files, partial code and code that doesn't build yet. It writes text, Markdown, JSON or SARIF 2.1.0, and `--fail-on high` makes it fail a CI build. `.github/workflows/contract-scan.yml` uploads results to GitHub code scanning.

## Mempool monitor

The monitor runs on a simulated DeFi market: a constant-product AMM with a TWAP oracle, a flash-loan pool and a lending market that prices collateral from either the spot price or the TWAP.

For each pending transaction it measures what the protocol would lose (valuing collateral at the TWAP, never the manipulated spot price), how far any pool is pushed from its TWAP, whether a flash loan pays for it and what the sender gains. It also looks for sandwich patterns across the pending transactions.

```
$ python -m defisentinel simulate
...
[CRITICAL] oracle-manipulation: would drain $3,795,768 from lend: pool price pushed 802% off its TWAP with a flash loan, sender nets $2,452,280
    response: guardian pauses lend ahead of the attack (gas 45 > 40) -> attack reverted
[MEDIUM] sandwich: mev-bot front-runs and back-runs user7's swap on TKN/USDC; victim receives 14,418.27 fewer TKN

attacker profit $0; market value $5,000,000 -> $5,000,000
```

For a live chain:

```bash
python -m defisentinel watch --rpc https://your-node --contract 0xYourLendingPool
```

The watcher polls pending transactions, decodes flash-loan entry points (Aave V3, Balancer, Uniswap V3, ERC-3156) and, when the node supports `debug_traceCall`, follows the call tree to find attack contracts that reach your protocol indirectly. Connect `on_alert` to your alerting or to a guardian key with pause rights.

## Quick start

```bash
pip install -r requirements.txt
python -m pytest -q
python -m defisentinel scan contracts/           # --format md|sarif|json --out FILE --fail-on high
python -m defisentinel simulate                  # --oracle twap, --no-guardian
python -m defisentinel smartbugs smartbugs-curated/
streamlit run app.py                             # dashboard
```

## Results

| Test | Result |
|---|---|
| Bundled vulnerable contracts | 11 and 12 findings; the fixed version has none |
| SmartBugs Curated, 143 real contracts with 208 labelled bugs | 49% of labelled lines found (56% in categories with a detector) |
| Simulated flash-loan oracle attack | $2.45M attacker profit without the monitor, $0 with it |

Details are in [docs/evaluation.md](docs/evaluation.md).

## Project layout

```
defisentinel/
  solidity.py   Solidity source model
  detectors.py  the detectors
  benchmark.py  SmartBugs scoring
  report.py     text, Markdown, JSON and SARIF output
  chain.py      simulated AMM, TWAP, flash loans and lending market
  monitor.py    transaction simulation, attack checks, guardian response
  scenario.py   simulated chain activity with a sandwich bot and an oracle attack
  rpc.py        live JSON-RPC watcher
contracts/      vulnerable and fixed example contracts
app.py          Streamlit dashboard
```

## Limitations

- The scanner matches patterns with light dataflow; it does not do symbolic execution. Use it as a fast first pass alongside Slither, Mythril and a manual audit.
- Denial-of-service, front-running and short-address bugs need analysis this scanner doesn't do.
- The simulated market models the mechanics needed for price and liquidity attacks. On mainnet, use an EVM fork such as Anvil or Tenderly for exact execution.
