from __future__ import annotations

# ruff: noqa: E402,I001

import sys
from pathlib import Path

import streamlit as st

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from dashboard.components.details import render_details
from dashboard.components.filters import common_filters
from dashboard.components.page import (
    configure_page,
    dashboard_database,
    render_sidebar_database_controls,
)
from dashboard.components.pagination import paginate_rows, render_pagination_controls
from dashboard.components.tables import render_table
from dashboard.data import queries, schemas

configure_page("Mods")

st.title("Mods")
database = dashboard_database()
render_sidebar_database_controls(database)

all_tab, prioritized_tab = st.tabs(["All mods", "Prioritized"])

with all_tab:
    rows = queries.enrich_mod_rows(database, queries.load_records(database, "mods"))
    filters = common_filters(rows, key_prefix="mods")
    filtered = queries.filter_records(
        rows,
        search=filters["search"],
        provider=filters["provider"],
        status=filters["status"],
        loader=filters["loader"],
        minecraft_version=filters["minecraft_version"],
        min_downloads=filters["min_downloads"],
    )
    page = render_pagination_controls(
        key_prefix="mods",
        total_items=len(filtered),
        page=filters["page"],
        page_size=filters["page_size"],
    )
    page_rows, _, _ = paginate_rows(filtered, page=page, page_size=filters["page_size"])
    table_column, details_column = st.columns([0.68, 0.32], gap="large")
    with table_column:
        selected = render_table(
            page_rows,
            key="mods_table",
            column_order=schemas.MODS.column_order,
            column_config=schemas.MODS.column_config,
            hidden_fields=schemas.MODS.hidden_fields,
        )
    with details_column:
        render_details(selected, title="Selected mod")

with prioritized_tab:
    prioritized = [
        {**row, "priority_score": row.get("score"), "repository": row.get("repository")}
        for row in queries.load_records(database, "prioritized_mods")
    ]
    st.caption("Ranked by modpack dependency presence and downloads.")
    table_column, details_column = st.columns([0.68, 0.32], gap="large")
    with table_column:
        selected_priority = render_table(
            prioritized,
            key="prioritized_mods_table",
            column_order=schemas.MODS.column_order,
            column_config=schemas.MODS.column_config,
            hidden_fields=schemas.MODS.hidden_fields,
        )
    with details_column:
        render_details(selected_priority, title="Selected prioritized mod")
