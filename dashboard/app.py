from __future__ import annotations

# ruff: noqa: E402,I001

import sys
from pathlib import Path

import streamlit as st

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from dashboard.components.metrics import render_overview_metrics
from dashboard.components.page import (
    configure_page,
    dashboard_database,
    render_sidebar_database_controls,
)
from dashboard.data import queries

configure_page("Dashboard")

st.title("MineModVulnIndexer")
st.caption("Read-only local dashboard backed by SQLite. No crawler or API call runs on page load.")

database = dashboard_database()
render_sidebar_database_controls(database)
if not database.exists():
    st.warning("SQLite database not found yet. Run a crawler command first, then refresh.")
    st.stop()

stats = queries.overview_stats(database)
render_overview_metrics(stats)

vulnerabilities = queries.load_records(database, "vulnerabilities")
findings = queries.load_records(database, "findings")
projects = queries.load_records(database, "provider_projects")

left, right = st.columns(2, gap="large")
with left:
    with st.container(border=True):
        st.subheader("Vulnerabilities by severity")
        st.caption("Severity distribution across indexed public advisories and candidates.")
        st.bar_chart(queries.counts_by(vulnerabilities, "severity"))
    with st.container(border=True):
        st.subheader("Findings by status")
        st.caption("Legacy exposure rows produced by version correlation.")
        st.bar_chart(queries.counts_by(findings, "status"))
with right:
    with st.container(border=True):
        st.subheader("Vulnerabilities by impact")
        st.caption("Impact categories inferred from public evidence.")
        st.bar_chart(queries.counts_by(vulnerabilities, "impact_category"))
    with st.container(border=True):
        st.subheader("Projects by provider")
        st.caption("Provider source coverage in the current local database.")
        st.bar_chart(queries.counts_by(projects, "provider"))
