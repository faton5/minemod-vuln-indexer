from typing import Any

import streamlit as st

from dashboard.data import queries


def common_filters(rows: list[dict[str, Any]], *, key_prefix: str) -> dict[str, Any]:
    with st.sidebar:
        st.subheader("Filters")
        search = st.text_input("Search", key=f"{key_prefix}_search")
        provider = st.selectbox(
            "Provider",
            queries.provider_options(rows),
            key=f"{key_prefix}_provider",
        )
        status = st.selectbox("Status", queries.status_options(rows), key=f"{key_prefix}_status")
        loader = st.selectbox("Loader", queries.loader_options(rows), key=f"{key_prefix}_loader")
        minecraft_version = st.selectbox(
            "Minecraft",
            queries.minecraft_version_options(rows),
            key=f"{key_prefix}_minecraft",
        )
        min_downloads = st.number_input(
            "Minimum downloads",
            min_value=0,
            value=0,
            step=1000,
            key=f"{key_prefix}_downloads",
        )
        page_size = st.number_input(
            "Rows per page",
            min_value=10,
            max_value=500,
            value=100,
            step=10,
            key=f"{key_prefix}_page_size",
        )
        page = st.number_input(
            "Page",
            min_value=1,
            value=1,
            step=1,
            key=f"{key_prefix}_page",
        )
    return {
        "search": search,
        "provider": provider,
        "status": status,
        "loader": loader,
        "minecraft_version": minecraft_version,
        "min_downloads": int(min_downloads),
        "page_size": int(page_size),
        "page": int(page),
    }
