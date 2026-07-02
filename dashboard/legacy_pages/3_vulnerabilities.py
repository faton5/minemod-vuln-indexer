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

configure_page("Vulnerabilities")

st.title("Vulnerabilities")
database = dashboard_database()
render_sidebar_database_controls(database)

rows = queries.load_records(database, "vulnerabilities")
filters = common_filters(
    rows,
    key_prefix="vulnerabilities",
    fields={"search", "status"},
)
filtered = queries.filter_records(
    rows,
    search=filters["search"],
    status=filters["status"],
)
page = render_pagination_controls(
    key_prefix="vulnerabilities",
    total_items=len(filtered),
    page=filters["page"],
    page_size=filters["page_size"],
)
page_rows, _, _ = paginate_rows(filtered, page=page, page_size=filters["page_size"])

st.caption("Candidates remain candidates until validated by reliable version evidence.")
table_column, details_column = st.columns([0.68, 0.32], gap="large")
with table_column:
    selected = render_table(
        page_rows,
        key="vulnerabilities_table",
        column_order=schemas.VULNERABILITIES.column_order,
        column_config=schemas.VULNERABILITIES.column_config,
        hidden_fields=schemas.VULNERABILITIES.hidden_fields,
    )
with details_column:
    render_details(selected, title="Selected vulnerability")
