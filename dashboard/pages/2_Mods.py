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

configure_page("Mods")

st.title("Mods")
st.caption("Mods indexes, popularite, repository et presence dans les modpacks.")

database = dashboard_database()
render_sidebar_database_controls(database)

rows = queries.enrich_mod_rows(database, queries.load_records(database, "mods"))

cols = st.columns(3)
cols[0].metric("Mods", len(rows))
cols[1].metric("Avec repository", sum(1 for row in rows if row.get("repository")))
cols[2].metric("Dans modpacks", sum(1 for row in rows if int(row.get("modpack_count") or 0) > 0))

search = st.text_input("Search mod")
provider = st.selectbox("Provider", queries.provider_options(rows))
filtered = queries.filter_records(rows, search=search, provider=provider)

render_table(
    filtered,
    key="mods_table",
    column_order=[
        "name",
        "provider",
        "download_count",
        "modpack_count",
        "vulnerability_count",
        "repository",
        "game_versions",
        "loaders",
    ],
)
