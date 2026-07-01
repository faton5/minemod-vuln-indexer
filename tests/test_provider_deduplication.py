from minemod_audit.providers.base import ProviderProject
from minemod_audit.providers.dedupe import deduplicate_provider_projects


def test_projects_are_deduplicated_by_normalized_repository_without_losing_provenance() -> None:
    projects = [
        ProviderProject(
            provider="modrinth",
            provider_project_id="AABBCCDD",
            slug="example",
            title="Example",
            project_type="mod",
            source_url="https://github.com/Owner/Repo",
        ),
        ProviderProject(
            provider="curseforge",
            provider_project_id="12345",
            slug="example",
            title="Example",
            project_type="mod",
            source_url="https://github.com/owner/repo.git",
        ),
    ]

    deduped = deduplicate_provider_projects(projects)

    assert len(deduped) == 1
    assert deduped[0].primary.provider == "modrinth"
    assert {item.provider for item in deduped[0].sources} == {"modrinth", "curseforge"}
