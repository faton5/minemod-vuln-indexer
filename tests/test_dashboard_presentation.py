from dashboard.components.pagination import clamp_page, paginate_rows
from dashboard.data.presentation import (
    format_compact_number,
    format_list_value,
    prepare_table,
    shorten_url,
    truncate_text,
)


def test_format_list_value_is_readable() -> None:
    assert format_list_value(["forge", "neoforge"]) == "Forge, NeoForge"
    assert format_list_value([]) == ""
    assert format_list_value({"loader": "fabric"}) == ""


def test_table_preparation_hides_raw_fields_and_keeps_original_rows() -> None:
    rows = [
        {
            "name": "Example",
            "loaders": ["fabric", "forge"],
            "summary": "x" * 120,
            "raw_metadata": {"api_key": "redacted"},
            "hashes": {"sha1": "a" * 40},
        }
    ]

    prepared = prepare_table(
        rows,
        column_order=["name", "loaders", "summary", "raw_metadata", "hashes"],
        hidden_fields={"raw_metadata", "hashes"},
    )

    assert list(prepared.frame.columns) == ["name", "loaders", "summary"]
    assert prepared.frame.loc[0, "loaders"] == "Fabric, Forge"
    assert str(prepared.frame.loc[0, "summary"]).endswith("...")
    assert prepared.original_rows[0]["raw_metadata"] == {"api_key": "redacted"}


def test_stable_selection_returns_original_row() -> None:
    prepared = prepare_table(
        [{"name": "A", "raw_metadata": {"full": True}}],
        column_order=["name"],
        hidden_fields={"raw_metadata"},
    )

    assert prepared.selected_original([0]) == {"name": "A", "raw_metadata": {"full": True}}
    assert prepared.selected_original([]) is None
    assert prepared.selected_original([5]) is None


def test_pagination_clamps_invalid_pages() -> None:
    rows = [{"id": index} for index in range(55)]

    assert clamp_page(page=99, total_items=len(rows), page_size=25) == 3
    assert clamp_page(page=0, total_items=len(rows), page_size=25) == 1
    page_rows, page, page_count = paginate_rows(rows, page=99, page_size=25)

    assert page == 3
    assert page_count == 3
    assert page_rows == rows[50:55]


def test_missing_fields_and_null_urls_are_safe() -> None:
    prepared = prepare_table(
        [{"name": None, "source_url": None, "tags": None}],
        column_order=["name", "source_url", "tags"],
        hidden_fields=set(),
    )

    assert prepared.frame.loc[0, "name"] == ""
    assert prepared.frame.loc[0, "source_url"] == ""
    assert prepared.frame.loc[0, "tags"] == ""


def test_number_and_url_formatting() -> None:
    assert format_compact_number(1_250_000) == "1.2 M"
    assert format_compact_number(350_000) == "350 k"
    assert shorten_url("https://github.com/example/mod/pull/42") == "github.com/.../42"


def test_truncate_text_uses_table_safe_length() -> None:
    assert truncate_text("a" * 90, limit=80) == ("a" * 77) + "..."
