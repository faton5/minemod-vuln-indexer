from pathlib import Path

from pytest import MonkeyPatch
from streamlit.testing.v1 import AppTest
from test_dashboard_queries import seed_dashboard_database


def test_dashboard_pages_load_with_fixture_database(
    monkeypatch: MonkeyPatch,
    tmp_path: Path,
) -> None:
    database = tmp_path / "dashboard.sqlite"
    seed_dashboard_database(database)
    monkeypatch.setenv("MINEMOD_DASHBOARD_DATABASE", str(database))

    app = AppTest.from_file("dashboard/app.py", default_timeout=5).run()

    assert not app.exception


def test_legacy_dashboard_pages_are_not_in_streamlit_navigation() -> None:
    assert not list(Path("dashboard/pages").glob("*.py"))
    assert list(Path("dashboard/legacy_pages").glob("*.py"))
