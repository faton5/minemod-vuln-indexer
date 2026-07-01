from typing import Any

from minemod_audit.config import Settings
from minemod_audit.providers.modrinth import ModrinthProvider, build_modrinth_user_agent


class FakeHttp:
    def __init__(self, responses: dict[tuple[str, int], Any]) -> None:
        self.responses = responses
        self.calls: list[tuple[str, dict[str, Any]]] = []
        self.last_rate_limit = {
            "limit": "300",
            "remaining": "299",
            "reset": "60",
        }

    def get_json(self, path: str, *, params: dict[str, Any] | None = None) -> Any:
        safe_params = params or {}
        self.calls.append((path, safe_params))
        offset = int(safe_params.get("offset", 0))
        return self.responses[(path, offset)]

    def close(self) -> None:
        return None


class PathFakeHttp:
    def __init__(self, responses: dict[str, Any]) -> None:
        self.responses = responses
        self.calls: list[tuple[str, dict[str, Any]]] = []
        self.last_rate_limit = {
            "limit": "300",
            "remaining": "299",
            "reset": "60",
        }

    def get_json(self, path: str, *, params: dict[str, Any] | None = None) -> Any:
        safe_params = params or {}
        self.calls.append((path, safe_params))
        return self.responses[path]

    def close(self) -> None:
        return None


def test_modrinth_user_agent_includes_contact_email() -> None:
    user_agent = build_modrinth_user_agent("0.1.0", "security@example.com")

    assert user_agent == (
        "faton5/minemod-vuln-indexer/0.1.0 "
        "(https://github.com/faton5/minemod-vuln-indexer; security@example.com)"
    )


def test_list_popular_mods_uses_public_api_without_token_and_download_sort() -> None:
    fake_http = FakeHttp(
        {
            (
                "/search",
                0,
            ): {
                "hits": [
                    {
                        "project_id": "AABBCCDD",
                        "slug": "example-mod",
                        "title": "Example Mod",
                        "project_type": "mod",
                        "downloads": 42,
                    }
                ]
            }
        }
    )
    provider = ModrinthProvider(Settings(), http=fake_http)

    projects = provider.list_popular_mods(limit=1, offset=0)

    assert projects[0].provider == "modrinth"
    assert projects[0].provider_project_id == "AABBCCDD"
    assert projects[0].project_type == "mod"
    assert projects[0].downloads == 42
    assert fake_http.calls[0][1]["index"] == "downloads"
    assert fake_http.calls[0][1]["facets"] == '[["project_type:mod"]]'


def test_list_popular_modpacks_paginates_until_limit() -> None:
    fake_http = FakeHttp(
        {
            ("/search", 0): {
                "hits": [
                    {
                        "project_id": "PACK0001",
                        "slug": "pack-1",
                        "title": "Pack 1",
                        "project_type": "modpack",
                    },
                    {
                        "project_id": "PACK0002",
                        "slug": "pack-2",
                        "title": "Pack 2",
                        "project_type": "modpack",
                    },
                ]
            },
            ("/search", 2): {
                "hits": [
                    {
                        "project_id": "PACK0003",
                        "slug": "pack-3",
                        "title": "Pack 3",
                        "project_type": "modpack",
                    }
                ]
            },
        }
    )
    provider = ModrinthProvider(Settings(), http=fake_http, page_size=2)

    projects = provider.list_popular_modpacks(limit=3, offset=0)

    assert [project.provider_project_id for project in projects] == [
        "PACK0001",
        "PACK0002",
        "PACK0003",
    ]


def test_versions_dependencies_and_hashes_are_normalized() -> None:
    fake_http = FakeHttp(
        {
            ("/project/example/version", 0): [
                {
                    "id": "VER00001",
                    "project_id": "AABBCCDD",
                    "version_number": "1.2.3",
                    "date_published": "2026-01-01T00:00:00Z",
                    "game_versions": ["1.20.1"],
                    "loaders": ["fabric"],
                    "dependencies": [
                        {
                            "project_id": "PARENT01",
                            "version_id": "DEPVER01",
                            "dependency_type": "required",
                        }
                    ],
                    "files": [
                        {
                            "filename": "example.jar",
                            "url": "https://cdn.modrinth.com/example.jar",
                            "hashes": {"sha512": "abc", "sha1": "def"},
                        }
                    ],
                }
            ]
        }
    )
    provider = ModrinthProvider(Settings(), http=fake_http)

    versions = provider.get_project_versions("example")

    assert versions[0].provider_version_id == "VER00001"
    assert versions[0].dependencies[0].dependency_type == "required"
    assert versions[0].files[0].hashes == {"sha512": "abc", "sha1": "def"}
    assert fake_http.calls[0][1]["include_changelog"] == "false"


def test_rate_limit_headers_are_exposed_from_http_client() -> None:
    fake_http = FakeHttp({("/search", 0): {"hits": []}})
    provider = ModrinthProvider(Settings(), http=fake_http)

    provider.list_popular_mods(limit=1, offset=0)

    assert provider.rate_limit_status() == {
        "limit": "300",
        "remaining": "299",
        "reset": "60",
    }


def test_get_versions_batches_ids_and_preserves_file_metadata() -> None:
    fake_http = PathFakeHttp(
        {
            "/versions": [
                {
                    "id": "DEPVER01",
                    "project_id": "MOD00001",
                    "version_number": "1.2.3",
                    "date_published": "2026-01-01T00:00:00Z",
                    "game_versions": ["1.20.1"],
                    "loaders": ["fabric"],
                    "files": [
                        {
                            "filename": "example-1.2.3.jar",
                            "hashes": {"sha512": "sha512-value", "sha1": "sha1-value"},
                            "primary": True,
                        }
                    ],
                }
            ]
        }
    )
    provider = ModrinthProvider(Settings(), http=fake_http)

    versions = provider.get_versions(["DEPVER01"])

    assert versions["DEPVER01"].provider_project_id == "MOD00001"
    assert versions["DEPVER01"].version_number == "1.2.3"
    assert versions["DEPVER01"].files[0].filename == "example-1.2.3.jar"
    assert versions["DEPVER01"].files[0].hashes == {
        "sha512": "sha512-value",
        "sha1": "sha1-value",
    }
    assert fake_http.calls == [("/versions", {"ids": '["DEPVER01"]'})]


def test_get_projects_batches_ids_and_preserves_source_url() -> None:
    fake_http = PathFakeHttp(
        {
            "/projects": [
                {
                    "id": "MOD00001",
                    "slug": "example-mod",
                    "title": "Example Mod",
                    "project_type": "mod",
                    "downloads": 42,
                    "source_url": "https://github.com/example/mod",
                    "issues_url": "https://github.com/example/mod/issues",
                }
            ]
        }
    )
    provider = ModrinthProvider(Settings(), http=fake_http)

    projects = provider.get_projects(["MOD00001"])

    assert projects["MOD00001"].title == "Example Mod"
    assert projects["MOD00001"].source_url == "https://github.com/example/mod"
    assert fake_http.calls == [("/projects", {"ids": '["MOD00001"]'})]
