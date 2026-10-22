"""DeFi Sentinel dashboard.

    streamlit run app.py
"""
from pathlib import Path

import pandas as pd
import plotly.graph_objects as go
import streamlit as st

from defisentinel.detectors import SEVERITY_ORDER, unit_findings
from defisentinel.scenario import run
from defisentinel.solidity import parse

st.set_page_config(page_title="DeFi Sentinel", layout="wide")
st.title("DeFi Sentinel")
tab_scan, tab_mon = st.tabs(["Contract scanner", "Mempool monitor"])
SEV_COLOR = {"critical": "red", "high": "orange", "medium": "blue", "low": "gray", "info": "gray"}

with tab_scan:
    samples = {p.name: p for p in sorted(Path("contracts").glob("*.sol"))}
    c1, c2 = st.columns([1, 2])
    choice = c1.selectbox("Bundled contract", list(samples))
    upload = c2.file_uploader("…or upload a .sol file", type=["sol"])
    name, src = (upload.name, upload.getvalue().decode("utf-8", "replace")) if upload else (choice, samples[choice].read_text())
    findings = unit_findings(parse(src, name))
    counts = {s: sum(f.severity == s for f in findings) for s in SEVERITY_ORDER}
    cols = st.columns(5)
    for col, (s, n) in zip(cols, counts.items()):
        col.metric(s.capitalize(), n)
    if not findings:
        st.success("No issues found by the detectors.")
    for f in findings:
        where = f"{f.contract}.{f.function}" if f.function else f.contract
        with st.expander(f":{SEV_COLOR[f.severity]}[{f.severity.upper()}] {f.title} · {where} · line {f.line}", expanded=f.severity == "critical"):
            st.code(f.snippet, language="solidity")
            st.write(f.detail)
            st.info(f"Fix: {f.fix}")
    with st.expander("Source"):
        st.code(src, language="solidity", line_numbers=True)

with tab_mon:
    st.caption("A simulated chain: ordinary users trade and borrow, a bot sandwiches a large swap at block 205, and an attacker "
               "launches a flash-loan oracle manipulation at block 209. Every pending transaction is simulated on a fork first.")
    c1, c2, c3 = st.columns(3)
    oracle = c1.radio("Lending market prices collateral from", ["spot", "twap"], horizontal=True)
    guardian = c2.toggle("Guardian can pause the market", value=True)
    seed = c3.number_input("Seed", 0, 999, 0)
    r = run(oracle, guardian, seed=int(seed))
    m1, m2, m3 = st.columns(3)
    m1.metric("Attacker profit", f"${r.attacker_profit:,.0f}")
    m2.metric("Market value", f"${r.market_value_end:,.0f}", f"{r.market_value_end - r.market_value_start:,.0f}")
    m3.metric("Alerts", len(r.alerts))
    df = pd.DataFrame(r.blocks)
    fig = go.Figure([go.Scatter(x=df["block"], y=df["price"], name="pool spot price"),
                     go.Scatter(x=df["block"], y=df["twap"], name="30-min TWAP", line=dict(dash="dot"))])
    fig.update_layout(height=280, yaxis_title="TKN price (USDC)", margin=dict(t=10))
    st.plotly_chart(fig, width="stretch")
    fig = go.Figure(go.Scatter(x=df["block"], y=df["market_value"], fill="tozeroy", name="recoverable market value"))
    fig.update_layout(height=220, yaxis_title="USD", margin=dict(t=10))
    st.plotly_chart(fig, width="stretch")
    for a in r.alerts:
        box = st.error if a.severity == "critical" else st.warning
        box(f"**Block {a.block} · {a.kind}** — {a.summary}" + (f"\n\nResponse: {a.response} → {'attack reverted' if a.protected else 'not stopped'}" if a.response else ""))
        if "trace" in a.details:
            st.dataframe(pd.DataFrame(a.details["trace"]), hide_index=True, width="stretch")
