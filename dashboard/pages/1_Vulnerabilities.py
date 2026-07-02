from __future__ import annotations

# ruff: noqa: E402,I001

import sys
from pathlib import Path

import streamlit as st

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from dashboard.components.details import render_details
from dashboard.components.page import (
    configure_page,
    dashboard_database,
    render_sidebar_database_controls,
)
from dashboard.components.tables import render_table
from dashboard.data import queries

configure_page("Vulnerabilities")

st.title("Vulnerabilities")
st.caption(
    "Candidats de correctifs publics, verdict IA, version corrigee et modpacks encore exposes."
)

database = dashboard_database()
render_sidebar_database_controls(database)

if not database.exists():
    st.warning("SQLite database not found yet.")
    st.stop()

rows = queries.security_candidate_rows(database)

cols = st.columns(4)
cols[0].metric("Candidats", len(rows))
cols[1].metric("Avec verdict IA", sum(1 for row in rows if row.get("ai_verdict")))
cols[2].metric(
    "Latest pack affecte",
    sum(1 for row in rows if row.get("exposure_status") == "latest_pack_still_affected"),
)
cols[3].metric("A revue manuelle", sum(1 for row in rows if row.get("requires_manual_review")))

if not rows:
    st.info(
        "Aucun candidat pour l'instant. Le crawler a peut-etre indexe les mods/modpacks, "
        "mais il n'a pas encore trouve de patch public assez solide a analyser."
    )
    st.stop()

search = st.text_input("Search mod, version, repository, verdict")
if search:
    rows = queries.filter_records(rows, search=search)

selected = render_table(
    rows,
    key="vulnerabilities_table",
    column_order=[
        "priority",
        "mod_name",
        "ai_verdict",
        "ai_confidence",
        "category",
        "confidence",
        "exposure_status",
        "affected_modpacks_count",
        "latest_affected_modpacks",
        "old_version",
        "fixed_version",
        "minecraft_version",
        "loader",
        "release_date",
    ],
    height=420,
)

if selected:
    st.divider()
    left, right = st.columns([0.55, 0.45], gap="large")
    with left:
        render_details(selected, title="Vulnerability detail", border=False)
    with right:
        st.subheader("Modpack exposure")
        affected = selected.get("affected_modpacks") or []
        if isinstance(affected, list) and affected:
            st.dataframe(
                affected,
                width="stretch",
                hide_index=True,
                column_order=[
                    "modpack",
                    "modpack_release",
                    "installed_version",
                    "fixed_version",
                    "latest_pack_release",
                    "same_minecraft_loader",
                    "days_since_fix",
                    "download_count",
                ],
            )
        else:
            st.info("No exact modpack exposure matched yet.")
