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

    page_paths = [
        "dashboard/app.py",
        "dashboard/pages/1_Vulnerabilities.py",
        "dashboard/pages/2_Mods.py",
        "dashboard/pages/3_Modpacks.py",
        "dashboard/pages/4_AI.py",
    ]

    for page_path in page_paths:
        app = AppTest.from_file(page_path, default_timeout=5).run()
        assert not app.exception, page_path


def test_legacy_dashboard_pages_are_not_in_streamlit_navigation() -> None:
    assert len(list(Path("dashboard/pages").glob("*.py"))) == 4
    assert list(Path("dashboard/legacy_pages").glob("*.py"))
