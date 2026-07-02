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
from dashboard.data import queries, schemas

configure_page("Runs")

st.title("Runs")
database = dashboard_database()
render_sidebar_database_controls(database)

rows = queries.load_records(database, "runs")
table_column, details_column = st.columns([0.68, 0.32], gap="large")
with table_column:
    selected = render_table(
        rows,
        key="runs_table",
        column_order=schemas.RUNS.column_order,
        column_config=schemas.RUNS.column_config,
        hidden_fields=schemas.RUNS.hidden_fields,
    )
with details_column:
    render_details(selected, title="Selected run")
