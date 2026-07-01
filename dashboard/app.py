from __future__ import annotations

import os
from pathlib import Path

import streamlit as st

from dashboard.components.metrics import render_overview_metrics
from dashboard.data import queries


def dashboard_database() -> Path:
    configured = os.environ.get("MINEMOD_DASHBOARD_DATABASE", "data/minemod.sqlite")
    return Path(configured)


st.set_page_config(
    page_title="MineModVulnIndexer Dashboard",
    page_icon="",
    layout="wide",
)

st.title("MineModVulnIndexer")
st.caption("Read-only local dashboard backed by SQLite. No crawler or API call runs on page load.")

database = dashboard_database()
st.sidebar.info(f"Database: `{database}`")
if st.sidebar.button("Refresh data"):
    st.cache_data.clear()
    st.rerun()

if not database.exists():
    st.warning(
        "SQLite database not found yet. Run a crawler command first, then refresh this page."
    )
    st.stop()

stats = queries.overview_stats(database)
render_overview_metrics(stats)

st.subheader("Provider status")
provider_projects = queries.load_records(database, "provider_projects")
provider_counts = queries.counts_by(provider_projects, "provider")
st.bar_chart(provider_counts)

st.subheader("Vulnerability distribution")
vulnerabilities = queries.load_records(database, "vulnerabilities")
left, right = st.columns(2)
with left:
    st.caption("By severity")
    st.bar_chart(queries.counts_by(vulnerabilities, "severity"))
with right:
    st.caption("By impact category")
    st.bar_chart(queries.counts_by(vulnerabilities, "impact_category"))

st.subheader("Finding status")
findings = queries.load_records(database, "findings")
st.bar_chart(queries.counts_by(findings, "status"))

st.caption(f"Last successful run: {stats.last_successful_run or 'unknown'}")
