import os
from pathlib import Path

import streamlit as st

from dashboard.components.details import render_details
from dashboard.components.filters import common_filters
from dashboard.components.tables import render_table
from dashboard.data import queries

database = Path(os.environ.get("MINEMOD_DASHBOARD_DATABASE", "data/minemod.sqlite"))
st.title("Mods")
all_tab, prioritized_tab = st.tabs(["All mods", "Prioritized"])

with all_tab:
    rows = queries.load_records(database, "mods")
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
    page = queries.paginate(filtered, page=filters["page"], page_size=filters["page_size"])
    st.caption(f"{len(filtered)} matching mods")
    selected = render_table(page, key="mods_table")
    render_details(selected, title="Selected mod")

with prioritized_tab:
    prioritized = queries.load_records(database, "prioritized_mods")
    st.caption("Ranked by modpack dependency presence and downloads.")
    selected_priority = render_table(prioritized, key="prioritized_mods_table")
    render_details(selected_priority, title="Selected prioritized mod")
