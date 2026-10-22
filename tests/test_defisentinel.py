import json
from pathlib import Path

import httpx

from defisentinel.chain import Tx, execute, genesis, oracle_attack
from defisentinel.detectors import unit_findings
from defisentinel.keccak import keccak256, selector
from defisentinel.monitor import Monitor
from defisentinel.report import sarif, scan_path
from defisentinel.rpc import analyse_tx, Client, watch
from defisentinel.scenario import run
from defisentinel.solidity import parse, strip_comments_and_strings

CONTRACTS = Path(__file__).resolve().parent.parent / "contracts"


def ids(path):
    return {f.id for f in unit_findings(parse((CONTRACTS / path).read_text(), path))}


def test_vulnerable_contracts_flagged():
    lending = ids("VulnerableLending.sol")
    assert {"spot-price-oracle", "reentrancy", "access-control", "tx-origin", "unchecked-call", "unchecked-erc20"} <= lending
    vault = ids("VulnerableVault.sol")
    assert {"unprotected-initializer", "arbitrary-delegatecall", "share-inflation", "weak-randomness",
            "msg-value-in-loop", "signature-replay", "divide-before-multiply"} <= vault


def test_fixed_contract_is_clean():
    assert ids("SafeLending.sol") == set()


def test_parser_ignores_braces_in_strings_and_comments():
    src = 'contract A { string s = "}{"; // }\n function f() public { /* { */ x = 1; } }'
    clean = strip_comments_and_strings(src)
    assert len(clean) == len(src) and "/*" not in clean
    u = parse(src)
    assert [f.name for f in u.contracts[0].functions] == ["f"]


def test_checks_effects_interactions_not_flagged():
    src = """pragma solidity 0.8.24; contract V { mapping(address=>uint) bal;
      function w(uint a) external { bal[msg.sender] -= a; (bool ok,) = msg.sender.call{value: a}(""); require(ok); } }"""
    assert not [f for f in unit_findings(parse(src)) if f.id in ("reentrancy", "unchecked-call")]


def test_keccak_vectors():
    assert keccak256(b"").hex() == "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470"
    assert selector("transfer(address,uint256)") == "0xa9059cbb"


def test_sarif_shape():
    s = sarif(scan_path(CONTRACTS))
    assert s["version"] == "2.1.0" and s["runs"][0]["results"]
    json.dumps(s)


def test_flash_loan_attack_spot_vs_twap():
    w = genesis("spot")
    r = execute(w, oracle_attack())
    assert r.ok and w.bal("attacker", "USDC") > 2_000_000
    w2 = genesis("twap")
    r2 = execute(w2, oracle_attack())
    assert not r2.ok and w2.bal("protocol:lend", "USDC") == 5_000_000  # reverted, untouched


def test_monitor_detects_and_guardian_protects():
    w = genesis("spot")
    mon = Monitor(w)
    attack = oracle_attack()
    alert = mon.inspect(attack)
    assert alert and alert.severity == "critical" and alert.details["flash_loan"]
    pause = mon.protect(alert, attack)
    assert alert.protected and pause.gas_price > attack.gas_price
    assert mon.inspect(Tx("user1", [("swap", "TKN/USDC", "USDC", 1000.0)])) is None


def test_scenario_outcomes():
    unprotected = run("spot", guardian=False)
    protected = run("spot", guardian=True)
    assert unprotected.attacker_profit > 1_000_000 and protected.attacker_profit <= 0
    assert any(a.kind == "sandwich" for a in protected.alerts)


def test_rpc_watcher_with_mock_node():
    flash_sel = selector("flashLoanSimple(address,address,uint256,bytes,uint16)")
    victim = "0x000000000000000000000000000000000000beef"

    def handler(request):
        body = json.loads(request.content)
        if body["method"] == "eth_getBlockByNumber":
            result = {"transactions": [
                {"hash": "0x1", "from": "0xattacker", "to": "0xattackcontract", "input": "0xdeadbeef", "value": "0x0"},
                {"hash": "0x2", "from": "0xuser", "to": "0xtoken", "input": selector("transfer(address,uint256)"), "value": "0x0"}]}
        else:  # debug_traceCall
            to = body["params"][0]["to"]
            result = {"to": to, "calls": [{"to": "0xaavepool", "input": flash_sel, "calls": [{"to": victim, "input": "0x"}]}]} \
                if to == "0xattackcontract" else {"to": to, "calls": []}
        return httpx.Response(200, json={"jsonrpc": "2.0", "id": body["id"], "result": result})

    alerts = watch("http://node", [victim], rounds=1, on_alert=lambda a: None, transport=httpx.MockTransport(handler))
    assert len(alerts) == 1 and alerts[0].tx_hash == "0x1" and "flash loan" in alerts[0].reason and victim in alerts[0].reason
