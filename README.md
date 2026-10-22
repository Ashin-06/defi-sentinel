# DeFi Sentinel

Two layers of protection for DeFi protocols:

1. **Before deployment:** a Solidity scanner for the bug classes behind the largest DeFi losses. It explains each finding in terms of how it gets exploited, and plugs into CI with SARIF.
2. **After deployment:** a mempool monitor that simulates every pending transaction on a fork of current state. It catches flash-loan oracle manipulation and sandwiches *before* they are confirmed, and has a guardian pause the market ahead of the attack.

## 1. Contract scanner

```
$ python -m defisentinel scan contracts/VulnerableLending.sol
contracts/VulnerableLending.sol:37  [CRITICAL] Price read from a manipulable spot source  (VulnerableLending.collateralPrice)
    (uint112 r0, uint112 r1, ) = pair.getReserves();
contracts/VulnerableLending.sol:59  [CRITICAL] State updated after external call (re-entrancy)  (VulnerableLending.withdrawEth)
    (bool ok, ) = msg.sender.call{value: amount}("");
contracts/VulnerableLending.sol:64  [CRITICAL] `setPriceFeed` is callable by anyone  (VulnerableLending.setPriceFeed)
...
```

| Detector | Real-world precedent |
|---|---|
| `spot-price-oracle`: price from `getReserves`, `slot0` or raw balances | bZx, Harvest, Inverse, Mango |
| `reentrancy`: state written after an external call, no guard (critical when ETH is sent) | The DAO, Cream, Fei/Rari |
| `access-control`: sensitive function (set*/mint/withdraw-all/upgrade/emergency..., writes to owner/oracle, `selfdestruct`/`delegatecall`) with no owner/role check | Poly Network, many `mint` bugs |
| `unprotected-initializer`: `initialize` with no `initializer` guard | Parity wallet, Wormhole implementation |
| `arbitrary-delegatecall`: delegatecall to a caller-chosen address | Parity, Furucombo |
| `tx-origin`: authorisation via `tx.origin` | phishing takeovers |
| `share-inflation`: 1:1 shares on an empty vault, no virtual offset | ERC4626 first-depositor attacks |
| `msg-value-in-loop`: `msg.value` counted on every iteration | Opyn, SushiSwap MISO |
| `signature-replay`: `ecrecover` without nonce/deadline | cross-chain replays |
| `weak-randomness`: block data (timestamp, number, blockhash, `now`) used as entropy | on-chain lotteries |
| `timestamp-dependence`: a condition decided by `block.timestamp` / `now` (SWC-116) | GovernMental, lottery timing |
| `unchecked-call` / `unchecked-erc20`: ignored success flags | USDT-style tokens returning false |
| `integer-overflow` (< 0.8 without SafeMath), `divide-before-multiply`, `selfdestruct`, `floating-pragma` | BEC token |

On the bundled contracts:
- `VulnerableLending.sol`: 11 findings, 4 critical.
- `VulnerableVault.sol`: 12 findings, 4 critical.
- `SafeLending.sol`, the same market with TWAP, checks-effects-interactions, `nonReentrant`, SafeERC20 and `onlyOwner`: **0 findings**.

### Measured on real contracts: SmartBugs Curated

`python -m defisentinel smartbugs smartbugs-curated/` scores the scanner on [SmartBugs Curated](https://github.com/ASSERT-KTH/smartbugs-curated): 143 real contracts, mostly from Etherscan, with 208 vulnerabilities labelled by line and category. Results are in `results/smartbugs.json`. A labelled bug counts as found when a detector of the same category reports within 3 lines of it.

| Category | Contracts flagged, first run → now | Labelled lines found, first run → now |
|---|---|---|
| Re-entrancy | 1 / 31 → **23 / 31** | 1 → **23** of 32 |
| Unchecked low-level calls | 25 / 52 → **52 / 52** | 31 → **68** of 75 |
| Access control | 15 / 18 | 9 of 24 |
| Arithmetic (pre-0.8 overflow) | 14 / 15 | 0 of 23 (file-level check, no line) |
| Bad randomness | 4 / 8 → 6 / 8 | 5 → 8 of 34 |
| Time manipulation | 0 / 5 → 2 / 5 | 0 → 1 of 7 |
| Denial of service, front-running, short address, other | 0 / 14 | 0 of 27 (no detector) |

Overall the scanner finds **49%** of labelled lines, 56% within the categories it has detectors for. About half of its line-level findings sit on a labelled line. The rest are not necessarily false: the contracts hold issues nobody labelled.

What the first run exposed:
- **Old call syntax was invisible.** Most of these real contracts use the pre-0.6 `msg.sender.call.value(x)()`, which the re-entrancy and unchecked-call detectors did not recognise.
- **Narrow randomness seeds.** The randomness check only covered `keccak256` and `%` patterns, missing `sha3`, `blockhash` and `now` seeds.

Both are fixed, and a timestamp-dependence check was added. The "now" column is measured on the same contracts that revealed the gaps, so treat it as in-sample. Denial-of-service, front-running and short-address bugs need dataflow or transaction-ordering analysis that this pattern scanner doesn't attempt; use Slither or Mythril for those.

The scanner has its own source model, which handles comments and strings safely and tracks line numbers. It needs **no compiler**, so it works on single files, partial code and code that doesn't build yet. Outputs are text, Markdown, JSON and **SARIF 2.1.0**, with `--fail-on high` for CI gates. `.github/workflows/contract-scan.yml` uploads the results to GitHub code scanning.

## 2. Mempool monitor

The monitor runs on a forkable DeFi world:
- a constant-product AMM with a TWAP oracle
- a flash-loan pool
- a lending market that prices collateral from either the **spot** price or the **TWAP**

Each pending transaction runs on a fork. The monitor measures what the protocol would lose, valuing collateral at the TWAP and never trusting the manipulated spot price. It also measures how far any pool is pushed off its TWAP, whether a flash loan funds the transaction, and what the sender gains. Across the pending set it looks for sandwiches.

```
$ python -m defisentinel simulate
block 209  price 1.020  twap 1.001  market $5,000,000
block 210  price 0.999  twap 1.001  market $5,000,000  [PAUSED]  ALERTS: oracle-manipulation
...
[CRITICAL] oracle-manipulation: would drain $3,795,768 from lend: pool price pushed 802% off its TWAP with a flash loan, sender nets $2,452,280
    response: guardian pauses lend ahead of the attack (gas 45 > 40) -> attack reverted
[MEDIUM] sandwich: mev-bot front-runs and back-runs user7's swap on TKN/USDC; victim receives 14,418.27 fewer TKN

attacker profit $0; market value $5,000,000 -> $5,000,000
```

| Setup | Attacker profit | Market value after |
|---|---|---|
| spot oracle, no monitor | **$2,452,280** | $1,349,729 (bad debt) |
| spot oracle, monitor + guardian pause | **$0** | $5,000,000 |
| TWAP oracle (fixed contract) | $0 (the attack reverts on its own) | $5,000,000 |

The attack: borrow $2M by flash loan, buy TKN to pump the pool price ~9×, deposit the TKN as collateral at the inflated price, borrow $4.49M, repay the flash loan. With a TWAP oracle the same transaction cannot repay its loan and reverts. That is the code-level fix, and the scanner recommends it.

### Live chains

```bash
python -m defisentinel watch --rpc https://your-node --contract 0xYourLendingPool --contract 0xYourVault
```

The watcher polls the pending block. It decodes selectors for flash-loan entry points (Aave V3 `flashLoan`/`flashLoanSimple`, Balancer, Uniswap V3 `flash`, ERC-3156), all derived at runtime with the built-in Keccak-256. When the node supports `debug_traceCall`, it walks the call tree to find attack contracts that reach your protocol indirectly. Wire `on_alert` to your pager or to a guardian key with pause rights.

## Run it

```bash
pip install -r requirements.txt
python -m pytest -q                              # 11 tests (includes a mocked JSON-RPC node)
python -m defisentinel smartbugs smartbugs-curated/   # recall on 143 labelled real contracts
python -m defisentinel scan contracts/           # --format md|sarif|json --out FILE --fail-on high
python -m defisentinel simulate [--oracle twap] [--no-guardian]
streamlit run app.py                             # scanner + monitor dashboard
```

## Layout

```
defisentinel/
  solidity.py   source model: contracts, functions, modifiers, state variables, lines
  detectors.py  15 function-level detectors + 2 file-level checks
  benchmark.py  scoring on the SmartBugs Curated labelled contracts
  report.py     text / Markdown / JSON / SARIF
  keccak.py     pure-Python Keccak-256 for selectors
  chain.py      forkable AMM + TWAP + flash loans + lending, atomic transactions with traces
  monitor.py    fork simulation, invariant checks, sandwich detection, guardian response
  scenario.py   simulated chain activity with a sandwich bot and an oracle attack
  rpc.py        live JSON-RPC watcher with selector decoding and call tracing
contracts/      vulnerable and fixed examples
app.py          Streamlit dashboard
```

## Limits

- The scanner is pattern- and dataflow-light, not a symbolic executor. Treat it as a fast first pass alongside Slither, Mythril and a human audit, not a replacement for them.
- The fork simulator models the protocol mechanics needed to reason about oracle and liquidity attacks. On mainnet, use an EVM fork (Anvil, Tenderly) for exact execution. The monitor's invariant checks stay the same.
