import os
from pathlib import Path

import streamlit as st

from dashboard.components.details import render_details
from dashboard.components.tables import render_table
from dashboard.data import queries

database = Path(os.environ.get("MINEMOD_DASHBOARD_DATABASE", "data/minemod.sqlite"))
st.title("Runs")
rows = queries.load_records(database, "runs")
selected = render_table(rows, key="runs_table")
render_details(selected, title="Selected run")
