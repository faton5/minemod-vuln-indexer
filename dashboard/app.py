from __future__ import annotations

# ruff: noqa: E402,I001

import sys
from pathlib import Path
from typing import Any

import streamlit as st

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from dashboard.components.details import render_details
from dashboard.components.page import (
    configure_page,
    dashboard_database,
    render_sidebar_database_controls,
)
from dashboard.data import queries

configure_page("Dashboard")

AI_VERDICT_RANK = {
    "confirmed_public_vulnerability": 5,
    "probable_exploitable_bug": 4,
    "interesting_security_fix": 3,
    "normal_bugfix": 2,
    "insufficient_evidence": 1,
    "unrelated": 0,
}


def main() -> None:
    _style()
    database = dashboard_database()
    render_sidebar_database_controls(database)

    st.title("MineModVulnIndexer")
    st.caption(
        "Cockpit local: candidats, preuves, IA Gemini et etat du crawl. "
        "Rien n'est lance depuis le dashboard."
    )

    if not database.exists():
        st.warning("SQLite database not found yet. Run a crawler command first, then refresh.")
        return

    kind_counts = queries.record_kind_counts(database)
    ai_usage = queries.ai_usage_stats(database)
    log_summary = queries.latest_log_summary(ROOT / "logs")
    candidates = _candidate_rows(database)
    mods = queries.load_records(database, "mods")
    modpacks = queries.load_records(database, "modpacks")

    _render_status_strip(kind_counts, ai_usage, log_summary)
    _render_attention(candidates)
    _render_ai_usage(ai_usage)
    _render_indexed_scope(kind_counts, mods, modpacks)
    _render_latest_log(log_summary)


def _render_status_strip(
    kind_counts: dict[str, int],
    ai_usage: dict[str, int],
    log_summary: dict[str, str],
) -> None:
    st.subheader("Etat actuel")
    cols = st.columns(5)
    cols[0].metric("Mods indexes", _fmt(kind_counts.get("mods", 0)))
    cols[1].metric("Modpacks", _fmt(kind_counts.get("modpacks", 0)))
    cols[2].metric("Releases", _fmt(kind_counts.get("modpack_releases", 0)))
    cols[3].metric("Candidats", _fmt(kind_counts.get("recent_security_fix_candidates", 0)))
    cols[4].metric("Analyses IA", _fmt(ai_usage["annotated_candidates"]))
    status = log_summary["status"]
    st.caption(
        f"Crawler: `{status}` | Dernier log: `{log_summary['name']}` | DB: `{dashboard_database()}`"
    )


def _render_attention(candidates: list[dict[str, Any]]) -> None:
    st.subheader("A verifier")
    st.caption(
        "Liste courte des candidats utiles. Si elle est vide, le crawler n'a pas encore trouve "
        "de patch public assez solide."
    )

    if not candidates:
        st.info(
            "Aucun candidat exploitable n'est encore en DB. Le crawler a indexe des mods/modpacks, "
            "mais il n'a pas encore trouve de changelog/PR/diff recent qui passe les filtres."
        )
        return

    visible = candidates[:50]
    selected_index = st.dataframe(
        visible,
        width="stretch",
        hide_index=True,
        column_order=[
            "priority",
            "mod_name",
            "ai_verdict",
            "ai_confidence",
            "category",
            "confidence",
            "old_version",
            "fixed_version",
            "affected_modpacks_count",
            "release_date",
        ],
        selection_mode="single-row",
        on_select="rerun",
        key="attention_candidates",
    )
    selection = getattr(selected_index, "selection", None)
    rows = getattr(selection, "rows", []) if selection is not None else []
    if rows:
        render_details(visible[rows[0]], title="Candidat selectionne")


def _render_ai_usage(ai_usage: dict[str, int]) -> None:
    st.subheader("Usage Gemini")
    cols = st.columns(4)
    cols[0].metric("Analyses sauvegardees", _fmt(ai_usage["cached_analyses"]))
    cols[1].metric("Cache hits candidats", _fmt(ai_usage["cache_hits"]))
    cols[2].metric("Input tokens", _fmt(ai_usage["input_tokens"]))
    cols[3].metric("Output tokens", _fmt(ai_usage["output_tokens"]))
    st.caption(
        "Le dashboard affiche les tokens retournes par l'API. Les credits/couts exacts "
        "dependent du compte Gemini et ne sont pas renvoyes comme une facture par cette API."
    )


def _render_indexed_scope(
    kind_counts: dict[str, int],
    mods: list[dict[str, Any]],
    modpacks: list[dict[str, Any]],
) -> None:
    st.subheader("Donnees indexees")
    left, right = st.columns([0.5, 0.5])
    with left:
        st.write("**Volumes utiles**")
        rows = [
            {"Type": "Provider projects", "Count": kind_counts.get("provider_projects", 0)},
            {"Type": "Provider versions", "Count": kind_counts.get("provider_versions", 0)},
            {"Type": "Modpack components", "Count": kind_counts.get("modpack_components", 0)},
            {"Type": "Gemini cache", "Count": kind_counts.get("gemini_analysis_cache", 0)},
        ]
        st.dataframe(rows, width="stretch", hide_index=True)
    with right:
        st.write("**Providers**")
        provider_counts = queries.counts_by([*mods, *modpacks], "provider")
        rows = [
            {"Provider": key or "unknown", "Count": value} for key, value in provider_counts.items()
        ]
        st.dataframe(rows, width="stretch", hide_index=True)


def _render_latest_log(log_summary: dict[str, str]) -> None:
    st.subheader("Dernier crawl")
    st.write(f"**Status**: `{log_summary['status']}`")
    st.write(f"**Log**: `{log_summary['name']}`")
    st.code(log_summary["last_line"], language="text")


def _candidate_rows(database: Path) -> list[dict[str, Any]]:
    rows = queries.load_records(database, "recent_security_fix_candidates")
    if not rows:
        rows = queries.load_records(database, "recent_fix_candidates")
    enriched: list[dict[str, Any]] = []
    for row in rows:
        copy = dict(row)
        affected = copy.get("affected_modpacks") or []
        copy["affected_modpacks_count"] = len(affected) if isinstance(affected, list) else 0
        copy["priority"] = _priority(copy)
        enriched.append(copy)
    return sorted(
        enriched,
        key=lambda item: (
            item["priority"],
            int(item.get("ai_confidence") or 0),
            int(item.get("confidence") or 0),
            item.get("release_date") or "",
        ),
        reverse=True,
    )


def _priority(row: dict[str, Any]) -> int:
    ai_rank = AI_VERDICT_RANK.get(str(row.get("ai_verdict") or ""), 0) * 100
    affected = row.get("affected_modpacks_count") or 0
    base = int(row.get("confidence") or 0)
    ai_confidence = int(row.get("ai_confidence") or 0)
    return ai_rank + ai_confidence + base + int(affected) * 10


def _fmt(value: int) -> str:
    return f"{value:,}".replace(",", " ")


def _style() -> None:
    st.markdown(
        """
        <style>
        .block-container { padding-top: 2rem; max-width: 1280px; }
        [data-testid="stMetricValue"] { font-size: 1.8rem; }
        [data-testid="stSidebarNav"] { display: none; }
        .stDataFrame { border: 1px solid rgba(255,255,255,.08); }
        </style>
        """,
        unsafe_allow_html=True,
    )


if __name__ == "__main__":
    main()
