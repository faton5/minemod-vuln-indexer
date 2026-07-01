import streamlit as st

from dashboard.data.view_models import OverviewStats

MetricRow = list[tuple[str, int | str]]


def render_overview_metrics(stats: OverviewStats) -> None:
    rows: list[MetricRow] = [
        [
            ("Mods", stats.mods),
            ("Modpacks", stats.modpacks),
            ("Recent actionable fixes", stats.recent_actionable_fixes),
            ("Legacy exposures", stats.legacy_exposures),
            ("Manual reviews", stats.manual_review),
        ],
        [
            ("Last crawl", stats.last_successful_run or "unknown"),
            ("GitHub status", stats.github_status),
            ("Modrinth status", stats.modrinth_status),
            ("CurseForge status", stats.curseforge_status),
            ("Database size", stats.database_size),
        ],
    ]
    for row in rows:
        columns = st.columns(len(row))
        for column, (label, value) in zip(columns, row, strict=True):
            column.metric(label, value)
