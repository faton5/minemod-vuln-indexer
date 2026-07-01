from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

import streamlit as st


@dataclass(frozen=True)
class TableSchema:
    column_order: list[str]
    column_config: dict[str, Any] = field(default_factory=dict)
    hidden_fields: set[str] = field(default_factory=set)


def link_column(label: str) -> Any:
    return st.column_config.LinkColumn(
        label,
        display_text=r"https?://(?:www\.)?([^/]+)/(?:.*/)?([^/]+)/?$",
    )


MODS = TableSchema(
    column_order=[
        "name",
        "provider",
        "download_count",
        "server_side",
        "client_side",
        "loaders",
        "game_versions",
        "repository",
        "priority_score",
        "vulnerability_count",
        "modpack_count",
    ],
    column_config={
        "download_count": st.column_config.TextColumn("Downloads"),
        "repository": link_column("Repository"),
    },
)

VULNERABILITIES = TableSchema(
    column_order=[
        "status",
        "confidence",
        "mod_name",
        "title",
        "severity",
        "impact_category",
        "attack_direction",
        "affected_versions",
        "fixed_versions",
        "source_url",
    ],
    column_config={
        "confidence": st.column_config.ProgressColumn(
            "Confidence",
            min_value=0,
            max_value=100,
        ),
        "source_url": link_column("Source"),
    },
)

RECENT_FIX_CANDIDATES = TableSchema(
    column_order=[
        "status",
        "confidence",
        "mod_name",
        "repository",
        "impact_category",
        "pull_request_url",
        "commit_url",
        "release_url",
        "release_version",
        "fixed_versions",
        "updated_at",
    ],
    column_config={
        "confidence": st.column_config.ProgressColumn(
            "Confidence",
            min_value=0,
            max_value=100,
        ),
        "pull_request_url": link_column("PR"),
        "commit_url": link_column("Commit"),
        "release_url": link_column("Release"),
    },
)

MODPACKS = TableSchema(
    column_order=[
        "name",
        "provider",
        "download_count",
        "minecraft_versions",
        "loaders",
        "release_count",
        "component_count",
        "finding_count",
        "highest_severity",
    ],
    column_config={"download_count": st.column_config.TextColumn("Downloads")},
)

FINDINGS = TableSchema(
    column_order=[
        "status",
        "confidence",
        "modpack_name",
        "modpack_release",
        "mod_name",
        "mod_version",
        "affected_range",
        "fixed_versions",
        "impact_category",
        "source_url",
    ],
    column_config={
        "confidence": st.column_config.ProgressColumn(
            "Confidence",
            min_value=0,
            max_value=100,
        ),
        "source_url": link_column("Source"),
    },
)

RUNS = TableSchema(
    column_order=["status", "started_at", "finished_at", "command", "duration_seconds"],
)

MANUAL_REVIEW = TableSchema(
    column_order=[
        "review_source",
        "status",
        "mod_name",
        "name",
        "repository",
        "requires_manual_review",
        "confidence",
    ],
)
