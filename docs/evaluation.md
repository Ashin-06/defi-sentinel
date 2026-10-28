# Evaluation

## Bundled contracts

- `VulnerableLending.sol`: 11 findings, 4 critical.
- `VulnerableVault.sol`: 12 findings, 4 critical.
- `SafeLending.sol`, the same market with a TWAP oracle, checks-effects-interactions, `nonReentrant`, SafeERC20 and `onlyOwner`: no findings.

## Real contracts: SmartBugs Curated

`python -m defisentinel smartbugs smartbugs-curated/` scores the scanner on [SmartBugs Curated](https://github.com/ASSERT-KTH/smartbugs-curated): 143 real contracts, mostly from Etherscan, with 208 vulnerabilities labelled by line and category. A labelled bug counts as found when a detector of the same category reports within 3 lines of it. Results go to `results/smartbugs.json`.

| Category | Contracts flagged, first run → now | Labelled lines found, first run → now |
|---|---|---|
| Re-entrancy | 1 / 31 → 23 / 31 | 1 → 23 of 32 |
| Unchecked low-level calls | 25 / 52 → 52 / 52 | 31 → 68 of 75 |
| Access control | 15 / 18 | 9 of 24 |
| Arithmetic (pre-0.8 overflow) | 14 / 15 | 0 of 23 (checked per file, not per line) |
| Bad randomness | 4 / 8 → 6 / 8 | 5 → 8 of 34 |
| Time manipulation | 0 / 5 → 2 / 5 | 0 → 1 of 7 |
| Denial of service, front-running, short address, other | 0 / 14 | 0 of 27 (no detector) |

Overall the scanner now finds 49% of labelled lines, and 56% within the categories it has detectors for. About half of its line-level findings fall on a labelled line; the rest are not necessarily wrong, since the contracts contain issues nobody labelled.

The first run showed two gaps. Most of these contracts use the old `msg.sender.call.value(x)()` syntax, which the re-entrancy and unchecked-call detectors didn't recognise, and the randomness check missed `sha3`, `blockhash` and `now`. Both were fixed and a timestamp check was added. The "now" figures are measured on the same contracts that revealed the gaps, so they are in-sample.

## Mempool simulation

`python -m defisentinel simulate` replays a flash-loan oracle attack and a sandwich bot on the simulated chain.

| Setup | Attacker profit | Market value after |
|---|---|---|
| Spot-price oracle, no monitor | $2,452,280 | $1,349,729 (bad debt) |
| Spot-price oracle, monitor and guardian pause | $0 | $5,000,000 |
| TWAP oracle (fixed contract) | $0 (the attack reverts) | $5,000,000 |

The attack borrows $2M by flash loan, buys TKN to push the pool price up about nine times, deposits the TKN as collateral at the inflated price, borrows $4.49M and repays the loan. With a TWAP oracle the same transaction can't repay its loan and reverts, which is the fix the scanner recommends.
