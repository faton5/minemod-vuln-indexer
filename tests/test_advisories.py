from pathlib import Path
from typing import Any, cast

from minemod_audit.advisories import GitHubClient


class FakeHttp:
    def __init__(self) -> None:
        self.queries: list[str] = []

    def get_json(self, path: str, *, params: dict[str, Any] | None = None) -> dict[str, Any]:
        assert path == "/search/issues"
        safe_params = params or {}
        self.queries.append(str(safe_params["q"]))
        return {"items": []}

    def close(self) -> None:
        return None


def test_search_security_issues_restricts_query_to_issues(tmp_path: Path) -> None:
    client = GitHubClient(
        token=None,
        cache_directory=tmp_path,
        timeout_seconds=5,
    )
    fake_http = FakeHttp()
    client.http = cast(Any, fake_http)

    client.search_security_issues("example/repo", terms=("security",), per_term=1)

    assert fake_http.queries == ["repo:example/repo security in:title,body is:issue"]
