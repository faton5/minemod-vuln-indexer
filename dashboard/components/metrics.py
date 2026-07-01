import streamlit as st

from dashboard.data.view_models import OverviewStats


def render_overview_metrics(stats: OverviewStats) -> None:
    rows = [
        [
            ("Mods", stats.mods),
            ("Modpacks", stats.modpacks),
            ("Releases", stats.releases),
            ("Components", stats.components),
        ],
        [
            ("Confirmed vulns", stats.confirmed_vulnerabilities),
            ("Candidate vulns", stats.candidate_vulnerabilities),
            ("Findings", stats.findings),
            ("Manual review", stats.manual_review),
        ],
    ]
    for row in rows:
        columns = st.columns(len(row))
        for column, (label, value) in zip(columns, row, strict=True):
            column.metric(label, value)
