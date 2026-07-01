from typing import Any

import streamlit as st


def render_details(row: dict[str, Any] | None, *, title: str = "Details") -> None:
    if row is None:
        st.caption("Select a row to inspect details.")
        return
    st.subheader(title)
    overview, raw = st.tabs(["Summary", "Raw metadata"])
    with overview:
        for key, value in row.items():
            if isinstance(value, (dict, list)):
                continue
            st.write(f"**{key.replace('_', ' ').title()}**: {value}")
    with raw:
        st.json(row, expanded=False)
