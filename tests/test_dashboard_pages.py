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
        "dashboard/pages/1_overview.py",
        "dashboard/pages/2_mods.py",
        "dashboard/pages/3_vulnerabilities.py",
        "dashboard/pages/4_modpacks.py",
        "dashboard/pages/5_findings.py",
        "dashboard/pages/6_manual_review.py",
        "dashboard/pages/7_runs.py",
        "dashboard/pages/8_recent_fix_candidates.py",
        "dashboard/pages/9_legacy_exposure.py",
    ]

    for page_path in page_paths:
        app = AppTest.from_file(page_path, default_timeout=5).run()
        assert not app.exception, page_path
