from __future__ import annotations

# ruff: noqa: E402,I001

import sys
from pathlib import Path

import streamlit as st

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from dashboard.components.metrics import render_overview_metrics
from dashboard.components.page import (
    configure_page,
    dashboard_database,
    render_sidebar_database_controls,
)
from dashboard.data import queries

configure_page("Overview")

st.title("Overview")
database = dashboard_database()
render_sidebar_database_controls(database)

stats = queries.overview_stats(database)
render_overview_metrics(stats)

vulnerabilities = queries.load_records(database, "vulnerabilities")
recent = queries.load_records(database, "recent_fix_candidates")
findings = queries.load_records(database, "findings")
projects = queries.load_records(database, "provider_projects")

left, right = st.columns(2, gap="large")
with left:
    with st.container(border=True):
        st.subheader("Recent fix statuses")
        st.caption("Recent public fix evidence grouped by triage status.")
        st.bar_chart(queries.counts_by(recent, "status"))
    with st.container(border=True):
        st.subheader("Legacy exposure status")
        st.caption("Correlated modpack exposure rows from version rules.")
        st.bar_chart(queries.counts_by(findings, "status"))
with right:
    with st.container(border=True):
        st.subheader("Vulnerability impact")
        st.caption("Impact category distribution for indexed vulnerabilities.")
        st.bar_chart(queries.counts_by(vulnerabilities, "impact_category"))
    with st.container(border=True):
        st.subheader("Provider coverage")
        st.caption("Indexed project metadata by provider.")
        st.bar_chart(queries.counts_by(projects, "provider"))
