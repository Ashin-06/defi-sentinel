# Threat model

What the scanning service protects, from whom, and what is still open. Written for the 1.0.0
code; nobody independent has reviewed it.

## What it protects

| Asset | Where it lives |
|---|---|
| Contract sources submitted for scanning | request bodies only; never stored |
| Scan results (findings, pass/fail, file hashes, who asked) | `scans` table |
| API keys | callers hold the key; the service holds only SHA-256 hashes |

Findings on unreleased contracts are sensitive: they are a list of ways to attack them.

## Threats and what stops them

| Threat | Mitigation | Residual risk |
|---|---|---|
| Someone reads findings for another team's contracts | API keys with roles; no CORS unless origins are listed | Every `viewer` sees every scan; there is no per-team scoping |
| Source code leaks from the service | Sources are scanned in memory and not stored; only hashes are kept | Logs never contain sources, but a crash dump of the process could |
| A CI gate is bypassed | `fail_on` is evaluated server-side and recorded with the scan | A pipeline can still ignore the answer; enforce it in branch protection |
| The scanner misses a bug | — | **Pattern matching with light dataflow, no symbolic execution.** 49% of labelled lines found on SmartBugs Curated. Use it alongside Slither, Mythril and a manual audit. |
| Denial of service with huge or pathological sources | 2 MB body cap, 200 files per scan, per-client rate limit | Regex-heavy parsing of adversarial input could still be slow; rate limit is per process |
| Errors leak data | Validation errors don't echo input; unhandled errors return only a request ID | — |

The mempool monitor and RPC watcher run as CLI tools against a node you choose; the API does not
expose them.

## Not covered

- TLS (terminate it at the ingress).
- Guardian keys: connecting `on_alert` to a key with pause rights is your deployment's job, and that
  key needs HSM-level protection.
