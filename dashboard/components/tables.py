from typing import Any

import streamlit as st

from dashboard.data.presentation import prepare_table


def render_table(
    rows: list[dict[str, Any]],
    *,
    key: str,
    column_order: list[str],
    column_config: dict[str, Any] | None = None,
    hidden_fields: set[str] | None = None,
    height: int = 650,
) -> dict[str, Any] | None:
    if not rows:
        st.info("No data available for the current filters.")
        return None
    prepared = prepare_table(
        rows,
        column_order=column_order,
        hidden_fields=hidden_fields or set(),
    )
    event: Any = st.dataframe(
        prepared.frame,
        width="stretch",
        height=height,
        row_height=38,
        hide_index=True,
        column_order=list(prepared.frame.columns),
        column_config=column_config or {},
        on_select="rerun",
        selection_mode="single-row",
        key=key,
    )
    selected_rows = event.selection.rows if event and event.selection else []
    return prepared.selected_original(list(selected_rows))
