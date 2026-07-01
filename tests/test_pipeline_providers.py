from pathlib import Path

import httpx
from pytest import MonkeyPatch

from minemod_audit.config import Settings
from minemod_audit.pipeline import Pipeline
from minemod_audit.providers.base import ProviderProject


class FakeModrinthProvider:
    name = "modrinth"

    def list_popular_mods(self, limit: int, offset: int = 0) -> list[ProviderProject]:
        del limit, offset
        return [
            ProviderProject(
                provider="modrinth",
                provider_project_id="AABBCCDD",
                slug="example",
                title="Example",
                project_type="mod",
            )
        ]

    def close(self) -> None:
        return None


class FailingCurseForgeProvider:
    name = "curseforge"

    def list_popular_mods(self, limit: int, offset: int = 0) -> list[ProviderProject]:
        del limit, offset
        request = httpx.Request("GET", "https://api.curseforge.com/v1/mods/search")
        response = httpx.Response(403, request=request)
        raise httpx.HTTPStatusError("Forbidden", request=request, response=response)

    def close(self) -> None:
        return None


class FakeRegistry:
    def __init__(self, *args: object, **kwargs: object) -> None:
        return None

    def enabled_provider_names(self, selector: str) -> list[str]:
        assert selector == "all"
        return ["modrinth", "curseforge"]

    def build_provider(self, name: str) -> object:
        if name == "modrinth":
            return FakeModrinthProvider()
        return FailingCurseForgeProvider()


def test_failing_curseforge_provider_does_not_block_modrinth(
    monkeypatch: MonkeyPatch,
    tmp_path: Path,
) -> None:
    monkeypatch.setattr("minemod_audit.pipeline.ProviderRegistry", FakeRegistry)
    settings = Settings(database=tmp_path / "test.db")
    pipeline = Pipeline(settings)

    mods = pipeline.collect_mods(limit=20, provider="all")

    assert [mod.provider for mod in mods] == ["modrinth"]
