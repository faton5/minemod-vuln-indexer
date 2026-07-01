from typing import Any

import streamlit as st

from dashboard.components.badges import status_badge
from dashboard.data.presentation import format_list_value, shorten_url

PRIMARY_FIELDS = [
    "mod_name",
    "name",
    "repository",
    "impact_category",
    "attack_direction",
    "affected_versions",
    "fixed_versions",
    "updated_at",
    "published_at",
    "release_version",
]

LINK_FIELDS = [
    "source_url",
    "pull_request_url",
    "commit_url",
    "release_url",
    "issue_url",
]


def render_details(
    row: dict[str, Any] | None,
    *,
    title: str = "Details",
    border: bool = True,
) -> None:
    with st.container(border=border):
        if row is None:
            st.caption("Select a row to inspect details.")
            return
        heading = str(row.get("title") or row.get("name") or row.get("mod_name") or title)
        st.subheader(heading)
        status = str(row.get("status") or "unknown")
        st.markdown(status_badge(status), unsafe_allow_html=True)
        confidence = row.get("confidence")
        if isinstance(confidence, int | float):
            st.progress(int(max(0, min(100, confidence))), text=f"Confidence {confidence}/100")

        for field in PRIMARY_FIELDS:
            if field in row and row.get(field) not in (None, "", []):
                st.write(f"**{_label(field)}**: {_format_value(row.get(field))}")

        links = [(field, row.get(field)) for field in LINK_FIELDS if row.get(field)]
        if links:
            st.write("**Links**")
            for field, value in links:
                st.link_button(_label(field), str(value), width="stretch")

        if row.get("patch_summary"):
            st.write("**Patch summary**")
            st.write(str(row["patch_summary"]))

        _render_expander("Evidence", row.get("evidence") or row.get("source_urls"))
        _render_expander("Changed files", row.get("changed_files"))
        _render_expander("Score reasons", row.get("reasons"))
        with st.expander("Raw metadata"):
            st.json(row, expanded=False)


def _render_expander(label: str, value: Any) -> None:
    if value in (None, "", []):
        return
    with st.expander(label):
        if isinstance(value, list):
            for item in value:
                st.write(_format_value(item))
        else:
            st.write(_format_value(value))


def _format_value(value: Any) -> str:
    if isinstance(value, list):
        return format_list_value(value)
    if isinstance(value, dict):
        return ""
    if isinstance(value, str) and value.startswith(("http://", "https://")):
        return shorten_url(value)
    return "" if value is None else str(value)


def _label(field: str) -> str:
    return field.replace("_", " ").title()
