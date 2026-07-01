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

configure_page("Manual Review")

st.title("Manual Review")
database = dashboard_database()
render_sidebar_database_controls(database)

items = []
for kind in (
    "repositories",
    "prioritized_mods",
    "security_signals",
    "vulnerabilities",
    "findings",
    "provider_project_groups",
):
    for row in queries.load_records(database, kind):
        unresolved_repository = kind == "repositories" and row.get("status") != "resolved"
        prioritized_without_repo = kind == "prioritized_mods" and not row.get("repository")
        provider_conflict = kind == "provider_project_groups" and row.get("conflicts")
        if (
            row.get("requires_manual_review")
            or unresolved_repository
            or prioritized_without_repo
            or provider_conflict
        ):
            copy = dict(row)
            copy["review_source"] = kind
            items.append(copy)

table_column, details_column = st.columns([0.68, 0.32], gap="large")
with table_column:
    selected = render_table(
        items,
        key="manual_review_table",
        column_order=schemas.MANUAL_REVIEW.column_order,
        column_config=schemas.MANUAL_REVIEW.column_config,
        hidden_fields=schemas.MANUAL_REVIEW.hidden_fields,
    )
with details_column:
    render_details(selected, title="Manual review item")
