import os
from pathlib import Path

import streamlit as st

from dashboard.components.metrics import render_overview_metrics
from dashboard.data import queries

database = Path(os.environ.get("MINEMOD_DASHBOARD_DATABASE", "data/minemod.sqlite"))
st.title("Overview")
if st.button("Refresh data"):
    st.cache_data.clear()
    st.rerun()

stats = queries.overview_stats(database)
render_overview_metrics(stats)

vulnerabilities = queries.load_records(database, "vulnerabilities")
findings = queries.load_records(database, "findings")
projects = queries.load_records(database, "provider_projects")

columns = st.columns(2)
with columns[0]:
    st.subheader("Vulnerabilities by severity")
    st.bar_chart(queries.counts_by(vulnerabilities, "severity"))
    st.subheader("Findings by status")
    st.bar_chart(queries.counts_by(findings, "status"))
with columns[1]:
    st.subheader("Vulnerabilities by impact")
    st.bar_chart(queries.counts_by(vulnerabilities, "impact_category"))
    st.subheader("Projects by provider")
    st.bar_chart(queries.counts_by(projects, "provider"))

st.caption(f"Last successful run: {stats.last_successful_run or 'unknown'}")
