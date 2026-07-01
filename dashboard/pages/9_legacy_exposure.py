import os
from pathlib import Path

import streamlit as st

from dashboard.components.details import render_details
from dashboard.components.tables import render_table
from dashboard.data import queries

database = Path(os.environ.get("MINEMOD_DASHBOARD_DATABASE", "data/minemod.sqlite"))
st.title("Legacy Exposure")
rows = queries.load_records(database, "findings")

st.caption(
    "Confirmed older vulnerabilities only appear here when a modpack contains a version "
    "that matches an affected or fixed-version rule."
)
selected = render_table(rows, key="legacy_exposure_table")
render_details(selected, title="Selected exposure")
