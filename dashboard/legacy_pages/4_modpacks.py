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

configure_page("Modpacks")

st.title("Modpacks")
database = dashboard_database()
render_sidebar_database_controls(database)

rows = queries.enrich_modpack_rows(database, queries.load_records(database, "modpacks"))
filters = common_filters(rows, key_prefix="modpacks")
filtered = queries.filter_records(
    rows,
    search=filters["search"],
    provider=filters["provider"],
    loader=filters["loader"],
    minecraft_version=filters["minecraft_version"],
    min_downloads=filters["min_downloads"],
)
page = render_pagination_controls(
    key_prefix="modpacks",
    total_items=len(filtered),
    page=filters["page"],
    page_size=filters["page_size"],
)
page_rows, _, _ = paginate_rows(filtered, page=page, page_size=filters["page_size"])

table_column, details_column = st.columns([0.68, 0.32], gap="large")
with table_column:
    selected = render_table(
        page_rows,
        key="modpacks_table",
        column_order=schemas.MODPACKS.column_order,
        column_config=schemas.MODPACKS.column_config,
        hidden_fields=schemas.MODPACKS.hidden_fields,
    )

with details_column:
    if selected is None:
        render_details(None, title="Selected modpack")
    else:
        with st.container(border=True):
            st.subheader(str(selected.get("name") or "Selected modpack"))
            summary_tab, releases_tab, components_tab, findings_tab = st.tabs(
                ["Summary", "Releases", "Components", "Findings"]
            )
            with summary_tab:
                render_details(selected, title="Summary", border=False)
            releases = [
                release
                for release in queries.load_records(database, "modpack_releases")
                if str(release.get("modpack_project_id")) == str(selected.get("project_id"))
            ]
            with releases_tab:
                selected_release = render_table(
                    releases,
                    key="modpack_releases_table",
                    column_order=[
                        "display_name",
                        "release_date",
                        "minecraft_version",
                        "loader",
                        "file_id",
                    ],
                    column_config={},
                    hidden_fields=set(),
                    height=300,
                )
            active_release = selected_release or (releases[0] if releases else None)
            with components_tab:
                components = [
                    component
                    for component in queries.load_records(database, "modpack_components")
                    if active_release
                    and str(component.get("modpack_file_id")) == str(active_release.get("file_id"))
                ]
                render_table(
                    components,
                    key="modpack_components_table",
                    column_order=[
                        "mod_name",
                        "mod_version",
                        "filename",
                        "provider",
                        "resolution_status",
                    ],
                    column_config={},
                    hidden_fields={"hashes"},
                    height=300,
                )
            with findings_tab:
                findings = [
                    finding
                    for finding in queries.normalize_finding_rows(
                        queries.load_records(database, "findings")
                    )
                    if str(finding.get("modpack_name")) == str(selected.get("name"))
                ]
                render_table(
                    findings,
                    key="modpack_findings_table",
                    column_order=schemas.FINDINGS.column_order,
                    column_config=schemas.FINDINGS.column_config,
                    hidden_fields=schemas.FINDINGS.hidden_fields,
                    height=300,
                )
