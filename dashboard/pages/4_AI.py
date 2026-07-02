from __future__ import annotations

# ruff: noqa: E402,I001

import sys
from pathlib import Path

import streamlit as st

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from dashboard.components.page import (
    configure_page,
    dashboard_database,
    render_sidebar_database_controls,
)
from dashboard.components.tables import render_table
from dashboard.data import queries

configure_page("AI")

st.title("Gemini AI")
st.caption("Usage, cache, verdicts et candidats enrichis par Gemini.")

database = dashboard_database()
render_sidebar_database_controls(database)

usage = queries.ai_usage_stats(database)
cache_rows = queries.load_records(database, "gemini_analysis_cache")
candidate_rows = [row for row in queries.security_candidate_rows(database) if row.get("ai_verdict")]

cols = st.columns(4)
cols[0].metric("Analyses cachees", usage["cached_analyses"])
cols[1].metric("Candidats avec IA", usage["annotated_candidates"])
cols[2].metric("Input tokens", usage["input_tokens"])
cols[3].metric("Output tokens", usage["output_tokens"])

st.caption(
    "Les tokens viennent des reponses API. "
    "Les credits/couts exacts restent a verifier cote console Gemini."
)

st.subheader("AI verdicts")
if candidate_rows:
    render_table(
        candidate_rows,
        key="ai_candidates_table",
        column_order=[
            "mod_name",
            "ai_verdict",
            "ai_confidence",
            "ai_category",
            "ai_public_information_level",
            "exposure_status",
            "affected_modpacks_count",
            "old_version",
            "fixed_version",
            "ai_model",
            "ai_cache_hit",
            "ai_analyzed_at",
        ],
        height=360,
    )
else:
    st.info("Aucun candidat reel n'a encore ete annote par Gemini dans la DB principale.")

st.subheader("AI cache")
if cache_rows:
    render_table(
        cache_rows,
        key="ai_cache_table",
        column_order=[
            "candidate_id",
            "model",
            "prompt_version",
            "schema_version",
            "input_token_count",
            "output_token_count",
            "status",
            "analyzed_at",
        ],
        height=360,
    )
else:
    st.info("Aucune entree cache Gemini dans la DB principale.")
