from typing import Any

import streamlit as st

from dashboard.components.pagination import PAGE_SIZE_OPTIONS
from dashboard.data import queries


def common_filters(
    rows: list[dict[str, Any]],
    *,
    key_prefix: str,
    fields: set[str] | None = None,
) -> dict[str, Any]:
    available = set().union(*(row.keys() for row in rows)) if rows else set()
    enabled = fields or {"search", "provider", "status", "loader", "minecraft", "downloads"}
    with st.sidebar:
        st.subheader("Filters")
        if st.button("Reset filters", key=f"{key_prefix}_reset_filters"):
            for suffix in ("search", "provider", "status", "loader", "minecraft", "downloads"):
                st.session_state.pop(f"{key_prefix}_{suffix}", None)
            st.rerun()
        search = st.text_input("Search", key=f"{key_prefix}_search") if "search" in enabled else ""
        provider = (
            st.selectbox("Provider", queries.provider_options(rows), key=f"{key_prefix}_provider")
            if "provider" in enabled and "provider" in available
            else "all"
        )
        status = (
            st.selectbox("Status", queries.status_options(rows), key=f"{key_prefix}_status")
            if "status" in enabled and "status" in available
            else "all"
        )
        loader = (
            st.selectbox("Loader", queries.loader_options(rows), key=f"{key_prefix}_loader")
            if "loader" in enabled and ({"loaders", "loader", "categories"} & available)
            else "all"
        )
        minecraft_version = (
            st.selectbox(
                "Minecraft",
                queries.minecraft_version_options(rows),
                key=f"{key_prefix}_minecraft",
            )
            if "minecraft" in enabled
            and (
                {"game_versions", "latest_versions", "minecraft_version", "minecraft_versions"}
                & available
            )
            else "all"
        )
        min_downloads = (
            st.number_input(
                "Minimum downloads",
                min_value=0,
                value=0,
                step=1000,
                key=f"{key_prefix}_downloads",
            )
            if "downloads" in enabled and ({"download_count", "downloads"} & available)
            else 0
        )
        page_size = st.selectbox(
            "Rows per page",
            PAGE_SIZE_OPTIONS,
            index=1,
            key=f"{key_prefix}_page_size",
        )
    return {
        "search": search,
        "provider": provider,
        "status": status,
        "loader": loader,
        "minecraft_version": minecraft_version,
        "min_downloads": int(min_downloads),
        "page_size": int(page_size),
        "page": int(st.session_state.get(f"{key_prefix}_page", 1)),
    }
