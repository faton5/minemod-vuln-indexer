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

configure_page("Findings")

st.title("Findings")
database = dashboard_database()
render_sidebar_database_controls(database)

rows = queries.normalize_finding_rows(queries.load_records(database, "findings"))
filters = common_filters(
    rows,
    key_prefix="findings",
    fields={"search", "status", "loader", "minecraft"},
)
filtered = queries.filter_records(
    rows,
    search=filters["search"],
    status=filters["status"],
    loader=filters["loader"],
    minecraft_version=filters["minecraft_version"],
)
page = render_pagination_controls(
    key_prefix="findings",
    total_items=len(filtered),
    page=filters["page"],
    page_size=filters["page_size"],
)
page_rows, _, _ = paginate_rows(filtered, page=page, page_size=filters["page_size"])

export_col_1, export_col_2, export_col_3 = st.columns(3)
export_col_1.download_button("CSV", queries.export_csv(filtered), "findings.csv", "text/csv")
export_col_2.download_button(
    "JSON",
    queries.export_json(filtered),
    "findings.json",
    "application/json",
)
export_col_3.download_button(
    "Markdown",
    queries.export_findings_markdown(filtered),
    "findings.md",
    "text/markdown",
)

table_column, details_column = st.columns([0.68, 0.32], gap="large")
with table_column:
    selected = render_table(
        page_rows,
        key="findings_table",
        column_order=schemas.FINDINGS.column_order,
        column_config=schemas.FINDINGS.column_config,
        hidden_fields=schemas.FINDINGS.hidden_fields,
    )
with details_column:
    render_details(selected, title="Selected finding")
