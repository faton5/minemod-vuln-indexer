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

    def list_recent_releases(self, repository: str, *, since: str) -> list[dict[str, Any]]:
        assert repository == "example/popular-lib"
        assert since
        return [
            {
                "html_url": "https://github.com/example/popular-lib/releases/tag/1.2.4",
                "tag_name": "1.2.4",
                "name": "1.2.4",
                "body": "Security fix for server-side validation. Commit abc123.",
                "published_at": "2026-06-01T00:00:00Z",
            }
        ]

    def list_recent_commits(self, repository: str, *, since: str) -> list[dict[str, Any]]:
        assert repository == "example/popular-lib"
        assert since
        return []

    def collect_global_advisories(self, repository: str) -> list[dict[str, Any]]:
        assert repository == "example/popular-lib"
        return []

    def search_recent_pull_requests(
        self,
        repository: str,
        *,
        terms: tuple[str, ...],
        since_date: str,
        per_term: int,
    ) -> list[dict[str, Any]]:
        assert repository == "example/popular-lib"
        assert "server-side validation" in terms
        assert since_date
        assert per_term == 3
        return [
            {
                "id": 42,
                "title": "Fix dupe with server-side validation",
                "body": "Do not trust client packets. Fixed in 1.2.4.",
                "html_url": "https://github.com/example/popular-lib/pull/42",
                "closed_at": "2026-06-01T00:00:00Z",
                "updated_at": "2026-06-01T00:00:00Z",
                "author_association": "MEMBER",
                "matched_terms": ["fix dupe", "server-side validation"],
            }
        ]

    def search_recent_issues(
        self,
        repository: str,
        *,
        terms: tuple[str, ...],
        since_date: str,
        per_term: int,
    ) -> list[dict[str, Any]]:
        del repository, terms, since_date, per_term
        return []

    def list_pull_request_commits(self, repository: str, pull_number: int) -> list[dict[str, Any]]:
        assert repository == "example/popular-lib"
        assert pull_number == 42
        return [{"sha": "abc123"}]

    def get_pull_request(self, repository: str, pull_number: int) -> dict[str, Any]:
        assert repository == "example/popular-lib"
        assert pull_number == 42
        return {
            "title": "Fix dupe with server-side validation",
            "body": "Do not trust client packets. Fixed in 1.2.4.",
            "html_url": "https://github.com/example/popular-lib/pull/42",
            "merged_at": "2026-06-01T00:00:00Z",
            "merge_commit_sha": "abc123",
            "author_association": "MEMBER",
            "matched_terms": ["fix dupe", "server-side validation"],
        }

    def get_commit_details(self, repository: str, sha: str) -> dict[str, Any]:
        assert repository == "example/popular-lib"
        assert sha == "abc123"
        return {
            "html_url": "https://github.com/example/popular-lib/commit/abc123",
            "files": [
                {
                    "filename": "src/PacketHandler.java",
                    "patch": (
                        "+ if (!player.hasPermission(node)) return;\n+ validatePacket(packet);"
                    ),
                }
            ],
        }

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
    assert stored[0].source_type == SourceType.PULL_REQUEST
    assert stored[0].status == "actionable"
    assert stored[0].confidence >= 70
    assert stored[0].fixed_versions == ["1.2.4"]
    assert "validation" in stored[0].title.lower()


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
