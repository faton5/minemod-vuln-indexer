from __future__ import annotations

from dataclasses import dataclass
from typing import Any
from urllib.parse import urlparse

import pandas as pd

Record = dict[str, Any]

DEFAULT_HIDDEN_FIELDS = {
    "raw",
    "raw_metadata",
    "hashes",
    "description",
    "body",
    "reasons",
    "evidence",
    "changed_files",
}

COUNT_FIELDS = {
    "download_count",
    "downloads",
    "priority_score",
}

PROGRESS_FIELDS = {
    "confidence",
}


@dataclass(frozen=True)
class PreparedTable:
    frame: pd.DataFrame
    original_rows: list[Record]

    def selected_original(self, selected_rows: list[int]) -> Record | None:
        if not selected_rows:
            return None
        selected_index = selected_rows[0]
        if selected_index < 0 or selected_index >= len(self.original_rows):
            return None
        return dict(self.original_rows[selected_index])


def format_list_value(value: Any) -> str:
    if value is None:
        return ""
    if not isinstance(value, list):
        return ""
    return ", ".join(_title_token(str(item)) for item in value if item is not None)


def truncate_text(value: Any, *, limit: int = 80) -> str:
    if value is None:
        return ""
    text = str(value).replace("\n", " ").strip()
    if len(text) <= limit:
        return text
    return f"{text[: max(0, limit - 3)]}..."


def format_compact_number(value: Any) -> str:
    try:
        number = int(value or 0)
    except (TypeError, ValueError):
        return ""
    if abs(number) >= 1_000_000:
        return f"{number / 1_000_000:.1f} M"
    if abs(number) >= 1_000:
        return f"{number // 1_000} k"
    return str(number)


def shorten_url(value: Any) -> str:
    if not value:
        return ""
    parsed = urlparse(str(value))
    if not parsed.netloc:
        return truncate_text(value, limit=80)
    last_segment = next((part for part in reversed(parsed.path.split("/")) if part), "")
    if last_segment:
        return f"{parsed.netloc}/.../{last_segment}"
    return parsed.netloc


def prepare_table(
    rows: list[Record],
    *,
    column_order: list[str],
    hidden_fields: set[str],
) -> PreparedTable:
    effective_hidden = set(hidden_fields) | DEFAULT_HIDDEN_FIELDS
    visible_columns = [column for column in column_order if column not in effective_hidden]
    table_rows = [
        {column: _format_cell(column, row.get(column)) for column in visible_columns}
        for row in rows
    ]
    return PreparedTable(
        frame=pd.DataFrame(table_rows, columns=visible_columns),
        original_rows=[dict(row) for row in rows],
    )


def _format_cell(column: str, value: Any) -> Any:
    if column in PROGRESS_FIELDS:
        return _format_progress_value(value)
    if value is None:
        return ""
    if isinstance(value, bool):
        return "Yes" if value else "No"
    if isinstance(value, list):
        return format_list_value(value)
    if isinstance(value, dict):
        return ""
    if column in COUNT_FIELDS:
        return format_compact_number(value)
    if isinstance(value, str) and len(value) > 80:
        return truncate_text(value)
    return value


def _format_progress_value(value: Any) -> int | float | None:
    if value is None or value == "":
        return None
    if isinstance(value, bool):
        return None
    if isinstance(value, int | float):
        return max(0, min(100, value))
    try:
        parsed = float(value)
    except (TypeError, ValueError):
        return None
    return max(0, min(100, parsed))


def _title_token(value: str) -> str:
    normalized = value.replace("_", " ").replace("-", " ").strip()
    known = {
        "api": "API",
        "cve": "CVE",
        "ghsa": "GHSA",
        "neoforge": "NeoForge",
        "nvd": "NVD",
        "rce": "RCE",
    }
    if normalized.lower() in known:
        return known[normalized.lower()]
    return " ".join(part.capitalize() for part in normalized.split())
