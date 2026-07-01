from minemod_audit.models import ModProject
from minemod_audit.repository import RepositoryCandidate, resolve_repository


def test_source_url_from_curseforge_is_trusted() -> None:
    mod = ModProject(
        project_id=231868,
        name="EnderCore",
        slug="endercore",
        authors=["SleepyTrousers"],
        download_count=10,
        source_url="https://github.com/SleepyTrousers/EnderCore",
    )

    result = resolve_repository(mod, overrides={}, candidates=[])

    assert result.repository == "SleepyTrousers/EnderCore"
    assert result.confidence == 100
    assert result.status == "resolved"


def test_ambiguous_github_search_is_not_marked_official() -> None:
    mod = ModProject(project_id=1, name="Example Mod", slug="example-mod", authors=["Alice"])
    candidates = [
        RepositoryCandidate(repository="someone/example-mod", score=72, source="github_search"),
        RepositoryCandidate(repository="other/example-mod", score=72, source="github_search"),
    ]

    result = resolve_repository(mod, overrides={}, candidates=candidates)

    assert result.repository is None
    assert result.confidence == 0
    assert result.status == "ambiguous"
