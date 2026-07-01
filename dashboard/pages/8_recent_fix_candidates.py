import os
from pathlib import Path

import streamlit as st

from dashboard.components.details import render_details
from dashboard.components.tables import render_table
from dashboard.data import queries

database = Path(os.environ.get("MINEMOD_DASHBOARD_DATABASE", "data/minemod.sqlite"))
st.title("Recent Fix Candidates")
rows = queries.load_records(database, "recent_fix_candidates")

show_weak = st.checkbox("Show weak signals", value=False)
visible_statuses = (
    {"actionable", "promising"}
    if not show_weak
    else {
        "actionable",
        "promising",
        "weak_signal",
    }
)
visible = [row for row in rows if row.get("status") in visible_statuses]

st.caption("Default view hides weak signals and rejected records.")
selected = render_table(visible, key="recent_fix_candidates_table")
render_details(selected, title="Selected evidence bundle")
