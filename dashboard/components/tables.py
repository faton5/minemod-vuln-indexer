from typing import Any

import pandas as pd
import streamlit as st


def render_table(rows: list[dict[str, Any]], *, key: str) -> dict[str, Any] | None:
    if not rows:
        st.info("No data available for the current filters.")
        return None
    frame = pd.DataFrame(rows)
    event: Any = st.dataframe(
        frame,
        use_container_width=True,
        hide_index=True,
        on_select="rerun",
        selection_mode="single-row",
        key=key,
    )
    selected_rows = event.selection.rows if event and event.selection else []
    if not selected_rows:
        return None
    return dict(rows[selected_rows[0]])
