from __future__ import annotations

# ruff: noqa: E402,I001

import sys
from pathlib import Path

import streamlit as st

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from dashboard.components.page import (
    configure_page,
    dashboard_database,
    render_sidebar_database_controls,
)
from dashboard.components.tables import render_table
from dashboard.data import queries

configure_page("Modpacks")

st.title("Modpacks")
st.caption("Modpacks indexes, releases lues et composants resolus.")

database = dashboard_database()
render_sidebar_database_controls(database)

rows = queries.enrich_modpack_rows(database, queries.load_records(database, "modpacks"))

cols = st.columns(4)
cols[0].metric("Modpacks", len(rows))
cols[1].metric("Releases", len(queries.load_records(database, "modpack_releases")))
cols[2].metric("Components", len(queries.load_records(database, "modpack_components")))
cols[3].metric("Avec findings", sum(1 for row in rows if int(row.get("finding_count") or 0) > 0))

search = st.text_input("Search modpack")
provider = st.selectbox("Provider", queries.provider_options(rows))
filtered = queries.filter_records(rows, search=search, provider=provider)

render_table(
    filtered,
    key="modpacks_table",
    column_order=[
        "name",
        "provider",
        "download_count",
        "release_count",
        "component_count",
        "finding_count",
        "minecraft_versions",
        "loaders",
    ],
)
