"""Vulnerability detectors. Each one targets a bug class behind real DeFi losses and
explains the exploit path and the fix in plain language."""
from __future__ import annotations

import re
from dataclasses import asdict, dataclass

from .solidity import Contract, Function, SourceUnit

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
ACCESS_MODIFIERS = re.compile(r"^(only\w*|auth|requiresAuth|ownerOnly|isOwner|whenAuthorized|restricted|onlyRole|initializer|reinitializer)$")
OWNER_CHECK = re.compile(r"(require\s*\(\s*(msg\.sender|_msgSender\(\))\s*==|if\s*\(\s*(msg\.sender|_msgSender\(\))\s*!=|_checkOwner\s*\(|_checkRole\s*\(|"
                         r"hasRole\s*\(|onlyOwner|require\s*\(\s*\w*(owner|admin|governance)\w*\s*==\s*msg\.sender|isAuthorized\s*\()", re.I)
# `.call.value(x)()` / `.call.gas(g)()` is the pre-0.6 spelling of `.call{value: x}()`, still common in deployed code
EXTERNAL_CALL = re.compile(r"(\.call\s*\{[^}]*\}\s*\(|\.call\s*(\.\s*(value|gas)\s*\([^()]*\)\s*)+\(|\.call\s*\(|\.send\s*\(|\.transfer\s*\(\s*[^,()]+\)|\.(safeTransfer|safeTransferFrom|transfer|transferFrom)\s*\()")
SENSITIVE_NAME = re.compile(r"^(set|update|change)[A-Z]\w*|^(mint|burn\w*|withdraw\w*|sweep\w*|rescue\w*|upgrade\w*|pause|unpause|kill|destroy|"
                            r"transferOwnership|renounceOwnership|emergency\w*|setOwner|grant\w*|revoke\w*|execute\w*|migrate\w*)$")


@dataclass
class Finding:
    id: str
    severity: str
    title: str
    contract: str
    function: str | None
    line: int
    snippet: str
    detail: str
    fix: str

    def as_dict(self):
        return asdict(self)


def _line(unit: SourceUnit, f: Function, rel: int) -> int:
    return unit.line_of(f.body_offset + 1 + rel)


def _statement_prefix(body: str, idx: int) -> str:
    """Text of the current statement up to idx (used to see if a call's result is consumed)."""
    start = max(body.rfind(";", 0, idx), body.rfind("{", 0, idx), body.rfind("}", 0, idx)) + 1
    return body[start:idx]


def _consumed(body: str, idx: int) -> bool:
    pre = _statement_prefix(body, idx)
    return bool(re.search(r"(require\s*\(|assert\s*\(|if\s*\(|return\b|=|\(\s*bool)", pre))


def _guarded(c: Contract, f: Function) -> bool:
    if any(ACCESS_MODIFIERS.match(m) for m in f.modifiers):
        return True
    if OWNER_CHECK.search(f.body):
        return True
    return any(OWNER_CHECK.search(c.modifiers[m].body) for m in f.modifiers if m in c.modifiers)


def _state_writes(c: Contract, body: str) -> list[re.Match]:
    names = "|".join(re.escape(v) for v in c.state_vars)
    if not names:
        return []
    return list(re.finditer(rf"\b({names})\b\s*(\[[^\]]*\]\s*)*(\.\w+\s*)*(=(?!=)|\+=|-=|\*=|/=|\+\+|--)|\bdelete\s+({names})\b", body))


def reentrancy(unit, c, f):
    if not f.mutates or not f.exposed or {"nonReentrant", "noReentrancy", "lock", "nonreentrant"} & set(f.modifiers):
        return
    writes = _state_writes(c, f.body)
    for call in EXTERNAL_CALL.finditer(f.body):
        text = call.group(0)
        if text.startswith(".send") or re.match(r"\.transfer\s*\(\s*[^,()]+\)$", text):
            continue  # ETH transfer/send forward 2300 gas: no meaningful re-entry
        later = [w for w in writes if w.start() > call.end()]
        if not later:
            continue
        w = later[0]
        ln = _line(unit, f, call.start())
        severity = "critical" if re.search(r"\.call\s*(\{[^}]*value|\.\s*value\s*\()", text) else ("high" if ".call" in text else "medium")
        yield Finding("reentrancy", severity, "State updated after external call (re-entrancy)",
                      c.name, f.name, ln, unit.line_text(ln),
                      f"`{f.name}` makes an external call and only afterwards writes `{w.group(1) or w.group(5)}` "
                      f"(line {_line(unit, f, w.start())}). The callee can re-enter `{f.name}` before the state "
                      "changes and repeat the payout: the pattern behind The DAO, Cream and many vault drains.",
                      "Apply checks-effects-interactions (update state before calling out) and add a `nonReentrant` guard.")
        return


def unchecked_call(unit, c, f):
    for m in re.finditer(r"\.(call|send|delegatecall|callcode)\s*(\{[^}]*\}|(\.\s*(value|gas)\s*\([^()]*\)\s*)*)\s*\(", f.body):
        if _consumed(f.body, m.start()):
            continue
        ln = _line(unit, f, m.start())
        yield Finding("unchecked-call", "high" if m.group(1) != "send" else "medium", "Return value of low-level call ignored",
                      c.name, f.name, ln, unit.line_text(ln),
                      f"The `{m.group(1)}` result is discarded. If the call fails the function carries on as if it succeeded, "
                      "e.g. marking a withdrawal paid that never arrived, or skipping a refund.",
                      "Capture the result: `(bool ok, ) = to.call{value: v}(\"\"); require(ok);` or use OpenZeppelin `Address.sendValue`.")


def tx_origin(unit, c, f):
    for m in re.finditer(r"tx\.origin\s*(==|!=)|(==|!=)\s*tx\.origin", f.body):
        ln = _line(unit, f, m.start())
        yield Finding("tx-origin", "high", "Authorisation with tx.origin", c.name, f.name, ln, unit.line_text(ln),
                      "`tx.origin` is the wallet that started the transaction, not the caller. A malicious contract the owner "
                      "interacts with can call this function and pass the check (phishing-style takeover).",
                      "Use `msg.sender` for authorisation.")


def access_control(unit, c, f):
    if c.kind in ("interface", "library") or not f.exposed or not f.mutates or f.kind != "function":
        return
    if f.name.lower() in ("initialize", "init", "initialise"):
        return  # covered by unprotected_initializer
    dangerous = SENSITIVE_NAME.match(f.name) or re.search(r"\bselfdestruct\s*\(|\.delegatecall\s*\(", f.body) or \
        re.search(r"\b(owner|admin|_owner|oracle|priceFeed|implementation|treasury|feeRecipient)\s*=(?!=)", f.body)
    if not dangerous or _guarded(c, f):
        return
    # user-scoped operations (withdraw own balance) are fine without access control
    if re.match(r"^withdraw", f.name) and re.search(r"\[\s*msg\.sender\s*\]", f.body) and not re.search(r"\ball\b|everything|Emergency", f.name, re.I):
        return
    yield Finding("access-control", "critical", f"`{f.name}` is callable by anyone", c.name, f.name, f.start_line, unit.line_text(f.start_line),
                  f"`{f.name}` changes privileged state or moves funds, but has no owner/role check. Anyone can call it, "
                  "which is how unprotected `mint`, `setOracle` and `initialize` bugs have drained protocols.",
                  "Restrict it (`onlyOwner` / `onlyRole(...)`) or make it internal.")


def unprotected_initializer(unit, c, f):
    if f.name.lower() in ("initialize", "init", "initialise") and f.exposed:
        if "initializer" in f.modifiers or "reinitializer" in f.modifiers or re.search(r"require\s*\(\s*!\s*\w*initiali[sz]ed", f.body) or \
                re.search(r"if\s*\(\s*\w*initiali[sz]ed\w*\s*\)\s*revert", f.body):
            return
        yield Finding("unprotected-initializer", "critical", "Initializer can be called again", c.name, f.name, f.start_line,
                      unit.line_text(f.start_line),
                      "`initialize` has no `initializer` modifier or initialized flag. An attacker can call it on the live "
                      "proxy (or the bare implementation) and make themselves owner.",
                      "Use OpenZeppelin `Initializable` (`initializer` modifier) and call `_disableInitializers()` in the implementation constructor.")


def spot_oracle(unit, c, f):
    hits = list(re.finditer(r"\.getReserves\s*\(|\.slot0\s*\(|balanceOf\s*\(\s*address\s*\(\s*this\s*\)\s*\)\s*\*|\*\s*\w*\.balanceOf\s*\(\s*address\s*\(\s*\w+\s*\)\s*\)\s*/", f.body))
    if not hits:
        return
    if re.search(r"(consult|observe|twap|TWAP|cumulative|latestRoundData)", f.body):
        return
    ln = _line(unit, f, hits[0].start())
    yield Finding("spot-price-oracle", "critical", "Price read from a manipulable spot source", c.name, f.name, ln, unit.line_text(ln),
                  "The price comes from current pool reserves / `slot0` / raw balances. A flash loan can move it by orders of "
                  "magnitude inside one transaction, borrow against the inflated value and repay: the bZx, Harvest, Inverse "
                  "and Mango pattern.",
                  "Use a manipulation-resistant oracle: a TWAP over many blocks, or Chainlink with staleness checks; cap per-block price moves.")


def arbitrary_delegatecall(unit, c, f):
    params = {p.split()[-1] for p in f.params if p.split()}
    for m in re.finditer(r"(\w+)\s*\.delegatecall\s*\(", f.body):
        if m.group(1) in params or f.exposed and not _guarded(c, f):
            ln = _line(unit, f, m.start())
            yield Finding("arbitrary-delegatecall", "critical", "delegatecall to a caller-controlled address", c.name, f.name, ln,
                          unit.line_text(ln),
                          "Delegatecall runs foreign code with this contract's storage and balance. If the target can be chosen by "
                          "the caller, they can overwrite the owner or self-destruct the contract (Parity wallet).",
                          "Only delegatecall to fixed, trusted implementations, behind access control.")


def weak_randomness(unit, c, f):
    seed = r"(block\.(timestamp|difficulty|prevrandao|number|coinbase|blockhash)|\bblockhash\s*\(|\bnow\b)"
    for m in re.finditer(rf"{seed}[^;]*%|(keccak256|sha3|sha256)\s*\([^;]*{seed}", f.body):
        ln = _line(unit, f, m.start())
        yield Finding("weak-randomness", "high", "Randomness from block data", c.name, f.name, ln, unit.line_text(ln),
                      "Block values are known to (and partly chosen by) validators and any contract in the same block can compute "
                      "the same 'random' number before acting.", "Use a VRF (e.g. Chainlink VRF) or commit-reveal.")
        return


def timestamp_dependence(unit, c, f):
    """SWC-116: a condition decided by the block timestamp, which the block producer can nudge."""
    for m in re.finditer(r"(if|require|while)\s*\([^;{]*\b(block\.timestamp|now)\b", f.body):
        ln = _line(unit, f, m.start())
        yield Finding("timestamp-dependence", "low", "Logic depends on the block timestamp", c.name, f.name, ln, unit.line_text(ln),
                      "Validators can shift the timestamp by several seconds. Fine for day-scale deadlines; unsafe when "
                      "seconds decide a winner, a price or a payout.", "Do not let short time windows decide value transfers.")
        return


def self_destruct(unit, c, f):
    for m in re.finditer(r"\bselfdestruct\s*\(", f.body):
        ln = _line(unit, f, m.start())
        yield Finding("selfdestruct", "medium", "selfdestruct present", c.name, f.name, ln, unit.line_text(ln),
                      "selfdestruct can permanently remove code paths and force-send ETH; after EIP-6780 its behaviour also changed.",
                      "Remove it; use pausing and upgrade paths instead.")


def unchecked_erc20(unit, c, f):
    for m in re.finditer(r"\.(transfer|transferFrom)\s*\(([^;]*)\)\s*;", f.body):
        if m.group(1) == "transfer" and "," not in m.group(2):
            continue  # address.transfer(value): ETH, reverts on failure
        if _consumed(f.body, m.start()):
            continue
        ln = _line(unit, f, m.start())
        yield Finding("unchecked-erc20", "medium", "ERC20 transfer result not checked", c.name, f.name, ln, unit.line_text(ln),
                      "Some tokens (USDT, BNB...) return false instead of reverting. The contract would credit a deposit or "
                      "settle a withdrawal that never moved.", "Use OpenZeppelin `SafeERC20.safeTransfer` / `safeTransferFrom`.")


def share_inflation(unit, c, f):
    if re.search(r"totalSupply\s*(\(\s*\))?\s*==\s*0", f.body) and re.search(r"(shares|share|mintAmount)\s*=\s*\w*(assets|amount)\b", f.body) \
            and not re.search(r"(_decimalsOffset|VIRTUAL|virtual|10\s*\*\*\s*\w*offset|DEAD|MINIMUM_LIQUIDITY)", unit.clean):
        ln = f.start_line
        yield Finding("share-inflation", "high", "First-depositor share inflation", c.name, f.name, ln, unit.line_text(ln),
                      "Shares are minted 1:1 when the vault is empty and priced from the token balance afterwards. The first "
                      "depositor can mint 1 wei of shares, donate tokens directly, and make every later deposit round down to 0 shares.",
                      "Use virtual shares/assets (OpenZeppelin ERC4626 decimals offset) or burn a minimum liquidity amount on first deposit.")


def msg_value_loop(unit, c, f):
    for m in re.finditer(r"\b(for|while)\s*\(", f.body):
        close = f.body.find("{", m.end())
        end = f.body.find("}", close)
        if close > 0 and "msg.value" in f.body[close:end]:
            ln = _line(unit, f, m.start())
            yield Finding("msg-value-in-loop", "high", "msg.value reused inside a loop", c.name, f.name, ln, unit.line_text(ln),
                          "Each iteration counts the same ETH again, so one payment is credited many times (Opyn, Sushi MISO).",
                          "Track the remaining value explicitly and subtract per iteration.")
            return


def signature_replay(unit, c, f):
    if re.search(r"\becrecover\s*\(|ECDSA\.recover\s*\(", f.body) and not re.search(r"nonce|usedSignatures|usedHashes|_useNonce|deadline", f.body, re.I):
        ln = f.start_line
        yield Finding("signature-replay", "high", "Signature can be replayed", c.name, f.name, ln, unit.line_text(ln),
                      "The signed message has no nonce or expiry, so the same signature can be submitted again (or on another chain).",
                      "Include a per-signer nonce, a deadline and the chain id / contract address (EIP-712 domain).")


def divide_before_multiply(unit, c, f):
    for m in re.finditer(r"\w+\s*/\s*\w+\s*\*\s*\w+", f.body):
        ln = _line(unit, f, m.start())
        yield Finding("divide-before-multiply", "low", "Division before multiplication", c.name, f.name, ln, unit.line_text(ln),
                      "Integer division truncates first, then the error is multiplied: rounding that attackers can farm in loops.",
                      "Multiply first, then divide (or use mulDiv).")
        return


FUNCTION_DETECTORS = [reentrancy, unchecked_call, tx_origin, access_control, unprotected_initializer, spot_oracle,
                      arbitrary_delegatecall, weak_randomness, timestamp_dependence, self_destruct, unchecked_erc20, share_inflation,
                      msg_value_loop, signature_replay, divide_before_multiply]


def unit_findings(unit: SourceUnit) -> list[Finding]:
    out: list[Finding] = []
    if unit.pragma:
        m = re.search(r"(\d+)\.(\d+)\.(\d+)", unit.pragma)
        if m and (int(m.group(1)), int(m.group(2))) < (0, 8) and "SafeMath" not in unit.raw:
            out.append(Finding("integer-overflow", "high", "Arithmetic without overflow checks", "-", None, 1, f"pragma solidity {unit.pragma};",
                               "Solidity < 0.8 wraps on overflow and the file does not use SafeMath (BEC token, 2018).",
                               "Upgrade to >=0.8 or use SafeMath everywhere."))
        if unit.pragma.startswith(("^", ">")):
            out.append(Finding("floating-pragma", "info", "Floating compiler version", "-", None, 1, f"pragma solidity {unit.pragma};",
                               "The contract may be deployed with a different compiler than the one it was tested with.",
                               "Pin an exact version, e.g. `pragma solidity 0.8.24;`."))
    for c in unit.contracts:
        if c.kind == "interface":
            continue
        for f in c.functions:
            for det in FUNCTION_DETECTORS:
                out.extend(det(unit, c, f))
    seen, uniq = set(), []
    for x in sorted(out, key=lambda x: (SEVERITY_ORDER[x.severity], x.line)):
        key = (x.id, x.contract, x.function, x.line)
        if key not in seen:
            seen.add(key)
            uniq.append(x)
    return uniq
