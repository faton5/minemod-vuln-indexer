from pathlib import Path
from typing import Any

from pytest import MonkeyPatch

from minemod_audit.config import Settings
from minemod_audit.models import ModpackComponent, PrioritizedMod, SourceType, Vulnerability
from minemod_audit.pipeline import Pipeline
from minemod_audit.providers.base import ProviderProject


class FakeProvider:
    name = "modrinth"

    def get_project(self, project_id_or_slug: str) -> ProviderProject:
        if project_id_or_slug == "popular":
            return ProviderProject(
                provider="modrinth",
                provider_project_id="popular",
                slug="popular-lib",
                title="Popular Lib",
                project_type="mod",
                downloads=5000,
                source_url="https://github.com/example/popular-lib",
            )
        return ProviderProject(
            provider="modrinth",
            provider_project_id=project_id_or_slug,
            slug="small-lib",
            title="Small Lib",
            project_type="mod",
            downloads=100,
        )

    def close(self) -> None:
        return None


class FakeRegistry:
    def __init__(self, *args: object, **kwargs: object) -> None:
        return None

    def build_provider(self, name: str) -> FakeProvider:
        assert name == "modrinth"
        return FakeProvider()


class FakeGitHubClient:
    def __init__(self, *args: object, **kwargs: object) -> None:
        self.closed = False

    def search_security_issues(
        self,
        repository: str,
        *,
        terms: tuple[str, ...],
        per_term: int,
    ) -> list[dict[str, Any]]:
        assert repository == "example/popular-lib"
        assert "CVE" in terms
        assert per_term == 3
        return [
            {
                "id": 42,
                "title": "CVE candidate: server crash on malformed packet",
                "body": "Security report for a denial of service issue.",
                "html_url": "https://github.com/example/popular-lib/issues/42",
                "state": "open",
                "matched_terms": ["CVE", "server crash"],
            }
        ]

    def search_repositories(
        self,
        mod_name: str,
        slug: str,
        authors: list[str],
    ) -> list[dict[str, Any]]:
        del mod_name, slug, authors
        return []

    def close(self) -> None:
        self.closed = True


def test_prioritize_mods_ranks_modpack_dependency_presence(
    monkeypatch: MonkeyPatch,
    tmp_path: Path,
) -> None:
    monkeypatch.setattr("minemod_audit.pipeline.ProviderRegistry", FakeRegistry)
    pipeline = Pipeline(Settings(database=tmp_path / "test.sqlite"))
    pipeline.store.replace_models(
        "modpack_components",
        [
            ModpackComponent(
                modpack_file_id="pack-a",
                mod_project_id="modrinth:popular",
                mod_file_id="version-a",
            ),
            ModpackComponent(
                modpack_file_id="pack-b",
                mod_project_id="modrinth:popular",
                mod_file_id="version-b",
            ),
            ModpackComponent(
                modpack_file_id="pack-c",
                mod_project_id="modrinth:small",
                mod_file_id="version-c",
            ),
        ],
        key=lambda item: f"{item.modpack_file_id}:{item.mod_project_id}:{item.mod_file_id}",
    )

    prioritized = pipeline.prioritize_mods(top=1, provider="modrinth")

    assert len(prioritized) == 1
    assert prioritized[0].name == "Popular Lib"
    assert prioritized[0].dependency_count == 2
    assert prioritized[0].source_url == "https://github.com/example/popular-lib"


def test_mine_security_signals_creates_candidate_vulnerabilities(
    monkeypatch: MonkeyPatch,
    tmp_path: Path,
) -> None:
    monkeypatch.setattr("minemod_audit.pipeline.GitHubClient", FakeGitHubClient)
    pipeline = Pipeline(Settings(database=tmp_path / "test.sqlite"))
    pipeline.store.replace_models(
        "prioritized_mods",
        [
            PrioritizedMod(
                project_id="modrinth:popular",
                provider="modrinth",
                provider_project_id="popular",
                name="Popular Lib",
                slug="popular-lib",
                download_count=5000,
                dependency_count=2,
                modpack_count=2,
                score=7000,
                source_url="https://github.com/example/popular-lib",
                repository="example/popular-lib",
            )
        ],
        key=lambda item: str(item.project_id),
    )

    vulnerabilities = pipeline.mine_security_signals(
        top=1,
        terms=("CVE", "server crash"),
        per_term=3,
    )

    stored = pipeline.store.load_models("vulnerabilities", Vulnerability)
    assert vulnerabilities == stored
    assert stored[0].mod_name == "Popular Lib"
    assert stored[0].source_type == SourceType.ISSUE
    assert stored[0].status == "candidate"
    assert stored[0].requires_manual_review is True
    assert "server crash" in stored[0].description.lower()


def test_correlate_skips_candidate_without_version_rules(tmp_path: Path) -> None:
    pipeline = Pipeline(Settings(database=tmp_path / "test.sqlite"))
    pipeline.store.replace_models(
        "modpack_components",
        [
            ModpackComponent(
                modpack_file_id="pack-version",
                mod_project_id="modrinth:popular",
                mod_file_id="mod-version",
                mod_name="Popular Lib",
                mod_version="1.2.3",
            )
        ],
        key=lambda item: f"{item.modpack_file_id}:{item.mod_project_id}:{item.mod_file_id}",
    )
    pipeline.store.replace_models(
        "vulnerabilities",
        [
            Vulnerability(
                internal_id="issue:1",
                mod_project_id="modrinth:popular",
                mod_name="Popular Lib",
                title="Candidate without affected versions",
                source_type=SourceType.ISSUE,
                source_url="https://github.com/example/popular-lib/issues/1",
                status="candidate",
                confidence=60,
                requires_manual_review=True,
            )
        ],
        key=lambda item: item.internal_id,
    )

    findings = pipeline.correlate()

    assert findings == []
