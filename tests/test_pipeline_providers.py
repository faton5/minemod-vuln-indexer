from pathlib import Path

import httpx
from pytest import MonkeyPatch

from minemod_audit.config import Settings
from minemod_audit.models import ModpackComponent, SourceType, Vulnerability
from minemod_audit.pipeline import Pipeline
from minemod_audit.providers.base import (
    ProviderDependency,
    ProviderFile,
    ProviderProject,
    ProviderVersion,
)


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


class EnrichingModrinthProvider:
    name = "modrinth"

    def list_popular_modpacks(self, limit: int, offset: int = 0) -> list[ProviderProject]:
        del limit, offset
        return [
            ProviderProject(
                provider="modrinth",
                provider_project_id="PACK0001",
                slug="example-pack",
                title="Example Pack",
                project_type="modpack",
            )
        ]

    def get_project_versions(self, project_id_or_slug: str) -> list[ProviderVersion]:
        assert project_id_or_slug == "PACK0001"
        return [
            ProviderVersion(
                provider="modrinth",
                provider_project_id="PACK0001",
                provider_version_id="PACKVER01",
                version_number="1.0.0",
                dependencies=[
                    ProviderDependency(
                        provider="modrinth",
                        provider_project_id="MOD0001",
                        provider_version_id="MODVER01",
                        dependency_type="required",
                    )
                ],
            )
        ]

    def get_versions(self, version_ids: list[str]) -> dict[str, ProviderVersion]:
        assert version_ids == ["MODVER01"]
        return {
            "MODVER01": ProviderVersion(
                provider="modrinth",
                provider_project_id="MOD0001",
                provider_version_id="MODVER01",
                version_number="1.2.3",
                loaders=["fabric"],
                game_versions=["1.20.1"],
                files=[
                    ProviderFile(
                        filename="example-1.2.3.jar",
                        hashes={"sha512": "sha512-value", "sha1": "sha1-value"},
                        primary=True,
                    )
                ],
            )
        }

    def get_projects(self, project_ids: list[str]) -> dict[str, ProviderProject]:
        assert project_ids == ["MOD0001"]
        return {
            "MOD0001": ProviderProject(
                provider="modrinth",
                provider_project_id="MOD0001",
                slug="example-mod",
                title="Example Mod",
                project_type="mod",
                source_url="https://github.com/example/mod",
            )
        }

    def close(self) -> None:
        return None


class UnresolvedModrinthProvider(EnrichingModrinthProvider):
    def get_project_versions(self, project_id_or_slug: str) -> list[ProviderVersion]:
        assert project_id_or_slug == "PACK0001"
        return [
            ProviderVersion(
                provider="modrinth",
                provider_project_id="PACK0001",
                provider_version_id="PACKVER01",
                version_number="1.0.0",
                dependencies=[
                    ProviderDependency(
                        provider="modrinth",
                        provider_project_id="MOD0001",
                        provider_version_id=None,
                        dependency_type="required",
                    )
                ],
            )
        ]

    def get_versions(self, version_ids: list[str]) -> dict[str, ProviderVersion]:
        assert version_ids == []
        return {}


class EnrichingRegistry:
    def __init__(self, *args: object, **kwargs: object) -> None:
        return None

    def enabled_provider_names(self, selector: str) -> list[str]:
        assert selector == "modrinth"
        return ["modrinth"]

    def build_provider(self, name: str) -> object:
        assert name == "modrinth"
        return EnrichingModrinthProvider()


class UnresolvedRegistry(EnrichingRegistry):
    def build_provider(self, name: str) -> object:
        assert name == "modrinth"
        return UnresolvedModrinthProvider()


def test_failing_curseforge_provider_does_not_block_modrinth(
    monkeypatch: MonkeyPatch,
    tmp_path: Path,
) -> None:
    monkeypatch.setattr("minemod_audit.pipeline.ProviderRegistry", FakeRegistry)
    settings = Settings(database=tmp_path / "test.db")
    pipeline = Pipeline(settings)

    mods = pipeline.collect_mods(limit=20, provider="all")

    assert [mod.provider for mod in mods] == ["modrinth"]


def test_modrinth_modpack_dependency_with_version_id_becomes_enriched_component(
    monkeypatch: MonkeyPatch,
    tmp_path: Path,
) -> None:
    monkeypatch.setattr("minemod_audit.pipeline.ProviderRegistry", EnrichingRegistry)
    pipeline = Pipeline(Settings(database=tmp_path / "test.db"))

    pipeline.collect_modpacks(limit=1, provider="modrinth")

    components = pipeline.store.load_models("modpack_components", ModpackComponent)
    assert len(components) == 1
    assert components[0].mod_name == "Example Mod"
    assert components[0].mod_version == "1.2.3"
    assert components[0].filename == "example-1.2.3.jar"
    assert components[0].provider == "modrinth"
    assert components[0].provider_project_id == "MOD0001"
    assert components[0].provider_version_id == "MODVER01"
    assert components[0].hashes == {"sha512": "sha512-value", "sha1": "sha1-value"}
    assert components[0].resolution_status == "resolved"
    pipeline.store.replace_models(
        "vulnerabilities",
        [
            Vulnerability(
                internal_id="GHSA-test",
                mod_project_id="modrinth:MOD0001",
                mod_name="Example Mod",
                title="Confirmed issue",
                source_type=SourceType.GHSA,
                source_url="https://github.com/advisories/GHSA-test",
                affected_versions=["<1.2.4"],
                fixed_versions=["1.2.4"],
                status="confirmed",
                confidence=100,
                requires_manual_review=False,
            )
        ],
        key=lambda item: item.internal_id,
    )

    findings = pipeline.correlate()

    assert len(findings) == 1
    assert findings[0].mod_name == "Example Mod"
    assert findings[0].mod_version == "1.2.3"


def test_modrinth_dependency_without_version_id_stays_unresolved_and_not_vulnerable(
    monkeypatch: MonkeyPatch,
    tmp_path: Path,
) -> None:
    monkeypatch.setattr("minemod_audit.pipeline.ProviderRegistry", UnresolvedRegistry)
    pipeline = Pipeline(Settings(database=tmp_path / "test.db"))
    pipeline.collect_modpacks(limit=1, provider="modrinth")
    pipeline.store.replace_models(
        "vulnerabilities",
        [
            Vulnerability(
                internal_id="GHSA-test",
                mod_project_id="modrinth:MOD0001",
                mod_name="Example Mod",
                title="Confirmed issue",
                source_type=SourceType.GHSA,
                source_url="https://github.com/advisories/GHSA-test",
                affected_versions=["<1.2.4"],
                fixed_versions=["1.2.4"],
                status="confirmed",
                confidence=100,
                requires_manual_review=False,
            )
        ],
        key=lambda item: item.internal_id,
    )

    components = pipeline.store.load_models("modpack_components", ModpackComponent)
    findings = pipeline.correlate()

    assert components[0].resolution_status == "unresolved"
    assert components[0].requires_manual_review is True
    assert components[0].mod_version is None
    assert findings == []
