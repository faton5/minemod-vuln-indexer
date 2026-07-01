import os
from pathlib import Path

import streamlit as st

from dashboard.components.details import render_details
from dashboard.components.filters import common_filters
from dashboard.components.tables import render_table
from dashboard.data import queries

database = Path(os.environ.get("MINEMOD_DASHBOARD_DATABASE", "data/minemod.sqlite"))
st.title("Modpacks")
rows = queries.load_records(database, "modpacks")
filters = common_filters(rows, key_prefix="modpacks")
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
selected = render_table(page, key="modpacks_table")
render_details(selected, title="Selected modpack")

if selected:
    releases = [
        release
        for release in queries.load_records(database, "modpack_releases")
        if str(release.get("modpack_project_id")) == str(selected.get("project_id"))
    ]
    st.subheader("Indexed releases")
    release = render_table(releases, key="modpack_releases_table")
    render_details(release, title="Selected release")
