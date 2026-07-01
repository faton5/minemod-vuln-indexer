import os
from pathlib import Path

import streamlit as st

from dashboard.components.details import render_details
from dashboard.components.filters import common_filters
from dashboard.components.tables import render_table
from dashboard.data import queries

database = Path(os.environ.get("MINEMOD_DASHBOARD_DATABASE", "data/minemod.sqlite"))
st.title("Findings")
rows = queries.load_records(database, "findings")
filters = common_filters(rows, key_prefix="findings")
filtered = queries.filter_records(
    rows,
    search=filters["search"],
    provider=filters["provider"],
    status=filters["status"],
    loader=filters["loader"],
    minecraft_version=filters["minecraft_version"],
    min_downloads=filters["min_downloads"],
)
page = queries.paginate(filtered, page=filters["page"], page_size=filters["page_size"])

st.download_button("Export filtered CSV", queries.export_csv(filtered), "findings.csv", "text/csv")
st.download_button(
    "Export filtered JSON",
    queries.export_json(filtered),
    "findings.json",
    "application/json",
)
st.download_button(
    "Export filtered Markdown",
    queries.export_findings_markdown(filtered),
    "findings.md",
    "text/markdown",
)
selected = render_table(page, key="findings_table")
render_details(selected, title="Selected finding")
