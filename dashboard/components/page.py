from __future__ import annotations

import os
from pathlib import Path

import streamlit as st


def configure_page(title: str) -> None:
    st.set_page_config(
        page_title=f"{title} · MineModVulnIndexer",
        page_icon="\U0001f6e1\ufe0f",
        layout="wide",
        initial_sidebar_state="expanded",
    )


def dashboard_database() -> Path:
    configured = os.environ.get("MINEMOD_DASHBOARD_DATABASE", "data/minemod.sqlite")
    return Path(configured)


def render_sidebar_database_controls(database: Path) -> None:
    st.sidebar.caption(f"Database: `{database}`")
    if st.sidebar.button("Refresh data", key="refresh_data"):
        st.cache_data.clear()
        st.rerun()
