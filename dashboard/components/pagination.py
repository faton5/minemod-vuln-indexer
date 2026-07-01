from __future__ import annotations

from math import ceil

import streamlit as st

PAGE_SIZE_OPTIONS = [25, 50, 100]


def page_count(total_items: int, page_size: int) -> int:
    if total_items <= 0:
        return 1
    return max(1, ceil(total_items / max(1, page_size)))


def clamp_page(*, page: int, total_items: int, page_size: int) -> int:
    return min(max(1, page), page_count(total_items, page_size))


def paginate_rows[T](rows: list[T], *, page: int, page_size: int) -> tuple[list[T], int, int]:
    safe_size = max(1, page_size)
    safe_page_count = page_count(len(rows), safe_size)
    safe_page = min(max(1, page), safe_page_count)
    start = (safe_page - 1) * safe_size
    return rows[start : start + safe_size], safe_page, safe_page_count


def render_pagination_controls(
    *,
    key_prefix: str,
    total_items: int,
    page: int,
    page_size: int,
) -> int:
    safe_page = clamp_page(page=page, total_items=total_items, page_size=page_size)
    safe_page_count = page_count(total_items, page_size)
    previous_col, info_col, next_col = st.columns([0.18, 0.64, 0.18])
    with previous_col:
        if st.button("Previous", disabled=safe_page <= 1, key=f"{key_prefix}_previous"):
            st.session_state[f"{key_prefix}_page"] = safe_page - 1
            st.rerun()
    with info_col:
        st.caption(f"Page {safe_page} / {safe_page_count} \u00b7 {total_items} results")
    with next_col:
        if st.button("Next", disabled=safe_page >= safe_page_count, key=f"{key_prefix}_next"):
            st.session_state[f"{key_prefix}_page"] = safe_page + 1
            st.rerun()
    st.session_state[f"{key_prefix}_page"] = safe_page
    return safe_page
