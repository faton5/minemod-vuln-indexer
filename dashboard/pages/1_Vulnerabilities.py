from __future__ import annotations

# ruff: noqa: E402,I001

import sys
from pathlib import Path
from typing import Any

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

configure_page("Vulnerabilities")

IMPORTANT_LEVELS = {"urgent", "high", "review"}


def main() -> None:
    _style()
    st.title("Vulnerabilities")
    st.caption(
        "Ecran d'enquete: bug suspecte, preuve publique, verdict IA, exposition modpack "
        "et logs de crawl. Le dashboard ne lance aucun test actif."
    )

    database = dashboard_database()
    render_sidebar_database_controls(database)

    if not database.exists():
        st.warning("SQLite database not found yet.")
        return

    rows = queries.security_candidate_rows(database)
    _render_metrics(rows)

    if not rows:
        st.info(
            "Aucun candidat pour l'instant. Le crawler a peut-etre indexe les mods/modpacks, "
            "mais il n'a pas encore trouve de patch public assez solide a analyser."
        )
        return

    filtered = _filter_rows(rows)
    if not filtered:
        st.info(
            "Aucun candidat actionnable avec les filtres actuels. "
            "Decoche le filtre utile pour explorer le bruit crawler/IA."
        )
        _render_all_candidates(rows)
        return

    selected = _select_candidate(filtered)
    if selected is None:
        return

    _render_candidate_workspace(database, selected)
    _render_all_candidates(filtered)


def _render_metrics(rows: list[dict[str, Any]]) -> None:
    interesting = [row for row in rows if row.get("dashboard_actionable")]
    cols = st.columns(5)
    cols[0].metric("Candidats", len(rows))
    cols[1].metric("A regarder", len(interesting))
    cols[2].metric("Avec verdict IA", sum(1 for row in rows if row.get("ai_verdict")))
    cols[3].metric(
        "Latest pack touche",
        sum(1 for row in rows if row.get("latest_affected_modpacks")),
    )
    cols[4].metric(
        "Modpacks touches",
        sum(int(row.get("affected_modpacks_count") or 0) for row in rows),
    )


def _filter_rows(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    left, right = st.columns([0.7, 0.3], gap="large")
    with left:
        search = st.text_input("Chercher mod, version, repo, verdict, changelog")
    with right:
        important_only = st.checkbox("Afficher seulement les candidats utiles", value=True)

    filtered = queries.filter_records(rows, search=search) if search else list(rows)
    if important_only:
        filtered = [row for row in filtered if row.get("dashboard_actionable")]
        if not filtered:
            st.warning("Aucun candidat ne passe le filtre utile.")
    return filtered


def _select_candidate(rows: list[dict[str, Any]]) -> dict[str, Any] | None:
    labels = [_candidate_label(row) for row in rows]
    if not labels:
        st.info("Aucun candidat ne correspond aux filtres.")
        return None
    selected_label = st.selectbox("Candidat a analyser", labels)
    return rows[labels.index(selected_label)]


def _render_candidate_workspace(database: Path, row: dict[str, Any]) -> None:
    st.divider()
    st.subheader(str(row.get("mod_name") or "Unknown mod"))
    _render_badges(row)
    st.write(str(row.get("risk_summary") or "No summary available."))

    cols = st.columns(4)
    cols[0].metric("Version suspecte", _text(row.get("old_version")))
    cols[1].metric("Version corrigee", _text(row.get("fixed_version")))
    cols[2].metric("IA confidence", _text(row.get("ai_confidence"), fallback="n/a"))
    cols[3].metric("Score crawler", _text(row.get("confidence"), fallback="n/a"))

    st.info(str(row.get("review_action") or "No action computed."))

    evidence_tab, ai_tab, modpacks_tab, logs_tab, raw_tab = st.tabs(
        ["Preuves", "IA", "Modpacks", "Logs", "Raw"]
    )
    with evidence_tab:
        _render_evidence(row)
    with ai_tab:
        _render_ai(row)
    with modpacks_tab:
        _render_modpacks(row)
    with logs_tab:
        _render_logs(database, row)
    with raw_tab:
        st.json(row)


def _render_badges(row: dict[str, Any]) -> None:
    labels = [
        str(row.get("attention_level") or "manual"),
        str(row.get("ai_label") or "AI: not analyzed"),
        str(row.get("category") or "unknown"),
        str(row.get("exposure_status") or "unknown exposure"),
    ]
    st.markdown(
        "<div class='badge-row'>"
        + "".join(f"<span class='badge'>{_html(label)}</span>" for label in labels)
        + "</div>",
        unsafe_allow_html=True,
    )


def _render_evidence(row: dict[str, Any]) -> None:
    left, right = st.columns([0.55, 0.45], gap="large")
    with left:
        st.write("**Probleme suspecte**")
        st.write(_text(row.get("potential_impact")))
        st.write("**Patch / verification ajoutee**")
        st.write(_text(row.get("ai_added_protection") or row.get("patch_summary")))
        st.write("**Ancien comportement accepte**")
        st.write(_text(row.get("ai_previous_behavior"), fallback="Pas encore explique par l'IA."))
    with right:
        st.write("**Fix**")
        st.write(_text(row.get("fix_status")))
        st.write("**Modpacks**")
        st.write(_text(row.get("modpack_status")))
        st.write("**Minecraft / loader**")
        st.write(f"{_text(row.get('minecraft_version'))} / {_text(row.get('loader'))}")

    st.write("**Liens publics**")
    links = [
        ("Repository", row.get("repository")),
        ("Issue", row.get("issue_url")),
        ("Pull request", row.get("pull_request_url")),
        ("Commit", row.get("commit_url")),
    ]
    rendered = [f"[{label}]({url})" for label, url in links if url]
    st.markdown(" | ".join(rendered) if rendered else "Aucun lien public resolu.")

    changed_files = row.get("changed_files") or []
    if isinstance(changed_files, list) and changed_files:
        st.write("**Fichiers modifies**")
        st.code("\n".join(str(item) for item in changed_files[:30]), language="text")

    st.write("**Changelog extrait**")
    st.code(_text(row.get("changelog_excerpt")), language="text")


def _render_ai(row: dict[str, Any]) -> None:
    if not row.get("ai_verdict") and not row.get("ai_status"):
        st.info("Gemini n'a pas encore analyse ce candidat.")
        return

    cols = st.columns(4)
    cols[0].metric("Verdict", _text(row.get("ai_verdict"), fallback="n/a"))
    cols[1].metric("Status", _text(row.get("ai_status"), fallback="n/a"))
    cols[2].metric("Confidence", _text(row.get("ai_confidence"), fallback="n/a"))
    cols[3].metric("Info publique", _text(row.get("ai_public_information_level"), fallback="n/a"))

    if row.get("ai_error"):
        st.error(f"AI error: {row['ai_error']}")

    st.write("**Explication IA**")
    st.write(_text(row.get("ai_concise_explanation"), fallback="Pas d'explication concise."))
    st.write("**Cause racine**")
    st.write(_text(row.get("ai_root_cause"), fallback="Non determinee."))
    st.write("**Protection ajoutee**")
    st.write(_text(row.get("ai_added_protection"), fallback="Non determinee."))
    st.write("**Impact possible**")
    st.write(_text(row.get("ai_potential_impact"), fallback="Non determine."))

    missing = row.get("ai_missing_information") or []
    contradictions = row.get("ai_contradictions") or []
    if missing:
        with st.expander("Informations manquantes"):
            st.write(missing)
    if contradictions:
        with st.expander("Contradictions detectees"):
            st.write(contradictions)


def _render_modpacks(row: dict[str, Any]) -> None:
    affected = row.get("affected_modpacks") or []
    if not isinstance(affected, list) or not affected:
        st.info("Aucun modpack ne matche exactement l'ancienne version pour l'instant.")
        return

    latest = [
        item for item in affected if isinstance(item, dict) and item.get("latest_pack_release")
    ]
    if latest:
        st.warning(
            f"{len(latest)} release(s) recente(s) de modpack utilisent encore l'ancienne version."
        )
    else:
        st.success(
            "Les matches actuels semblent concerner seulement d'anciennes releases de modpack."
        )

    st.dataframe(
        sorted(
            [item for item in affected if isinstance(item, dict)],
            key=lambda item: (
                bool(item.get("latest_pack_release")),
                int(item.get("download_count") or 0),
            ),
            reverse=True,
        ),
        width="stretch",
        hide_index=True,
        column_order=[
            "modpack",
            "modpack_release",
            "installed_version",
            "fixed_version",
            "latest_pack_release",
            "same_minecraft_loader",
            "days_since_fix",
            "download_count",
        ],
    )


def _render_logs(database: Path, row: dict[str, Any]) -> None:
    candidate_id = str(row.get("candidate_id") or "")
    events = queries.crawler_events(database, candidate_id=candidate_id)
    if not events:
        st.info("Aucun log structure pour ce candidat. Relance le crawler pour en produire.")
        return
    st.dataframe(
        events,
        width="stretch",
        hide_index=True,
        column_order=["created_at", "stage", "level", "message", "data"],
    )


def _render_all_candidates(rows: list[dict[str, Any]]) -> None:
    with st.expander("Table complete des candidats", expanded=False):
        render_table(
            rows,
            key="vulnerabilities_table",
            column_order=[
                "attention_level",
                "priority",
                "mod_name",
                "risk_summary",
                "ai_label",
                "ai_confidence",
                "modpack_status",
                "old_version",
                "fixed_version",
                "minecraft_version",
                "loader",
                "release_date",
            ],
            height=420,
        )


def _candidate_label(row: dict[str, Any]) -> str:
    return (
        f"{row.get('attention_level') or 'manual'} | "
        f"{row.get('mod_name') or 'Unknown mod'} | "
        f"{row.get('old_version') or '?'} -> {row.get('fixed_version') or '?'} | "
        f"{row.get('affected_modpacks_count') or 0} packs | "
        f"{row.get('ai_verdict') or row.get('category') or 'no verdict'}"
    )


def _text(value: object, *, fallback: str = "Unknown") -> str:
    if value is None:
        return fallback
    text = str(value).strip()
    return text if text else fallback


def _html(value: object) -> str:
    return (
        str(value)
        .replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
    )


def _style() -> None:
    st.markdown(
        """
        <style>
        .block-container { padding-top: 2rem; max-width: 1320px; }
        [data-testid="stMetricValue"] { font-size: 1.45rem; }
        .badge-row { display: flex; flex-wrap: wrap; gap: .45rem; margin: .35rem 0 1rem; }
        .badge {
            border: 1px solid rgba(255,255,255,.16);
            border-radius: 999px;
            padding: .24rem .62rem;
            font-size: .82rem;
            background: rgba(255,255,255,.04);
        }
        </style>
        """,
        unsafe_allow_html=True,
    )


if __name__ == "__main__":
    main()
