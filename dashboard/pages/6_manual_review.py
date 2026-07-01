import os
from pathlib import Path

import streamlit as st

from dashboard.components.details import render_details
from dashboard.components.tables import render_table
from dashboard.data import queries

database = Path(os.environ.get("MINEMOD_DASHBOARD_DATABASE", "data/minemod.sqlite"))
st.title("Manual Review")

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
            row["review_source"] = kind
            items.append(row)

selected = render_table(items, key="manual_review_table")
render_details(selected, title="Manual review item")
