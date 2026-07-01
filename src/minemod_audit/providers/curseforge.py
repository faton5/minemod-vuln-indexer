import logging
from typing import Any

import httpx

from minemod_audit.config import Settings
from minemod_audit.curseforge import CurseForgeClient
from minemod_audit.providers.base import (
    ProviderDependency,
    ProviderName,
    ProviderProject,
    ProviderStatus,
    ProviderVersion,
)

LOGGER = logging.getLogger(__name__)


class CurseForgeProvider:
    name: ProviderName = "curseforge"

    def __init__(
        self,
        settings: Settings,
        *,
        offline: bool = False,
        refresh: bool = False,
    ) -> None:
        api_key = (settings.curseforge_api_key or "").strip()
        if not api_key:
            raise ValueError("CurseForge API key is required")
        self.client = CurseForgeClient(
            api_key=api_key,
            cache_directory=settings.cache_directory,
            timeout_seconds=settings.timeout_seconds,
            offline=offline,
            refresh=refresh,
        )

    def close(self) -> None:
        self.client.close()

    def health_check(self) -> ProviderStatus:
        try:
            self.client.http.get_json("/v1/games", params={"pageSize": 1})
        except httpx.HTTPStatusError as exc:
            if exc.response.status_code in {401, 403}:
                return ProviderStatus(
                    name="CurseForge",
                    status="disabled",
                    priority=2,
                    reason=f"API key rejected with HTTP {exc.response.status_code}",
                )
            raise
        return ProviderStatus(
            name="CurseForge",
            status="enabled",
            priority=2,
            reason="API key configured",
        )

    def list_popular_mods(self, limit: int, offset: int = 0) -> list[ProviderProject]:
        del offset
        return [self._project_from_mod(item.raw) for item in self.client.collect_mods(limit=limit)]

    def list_popular_modpacks(self, limit: int, offset: int = 0) -> list[ProviderProject]:
        del offset
        return [
            ProviderProject(
                provider="curseforge",
                provider_project_id=str(item.project_id),
                slug=item.slug,
                title=item.name,
                project_type="modpack",
                downloads=item.download_count,
                raw_metadata=item.model_dump(mode="json"),
            )
            for item in self.client.collect_modpacks(limit=limit)
        ]

    def get_project(self, project_id_or_slug: str) -> ProviderProject:
        payload = self.client.http.get_json(f"/v1/mods/{project_id_or_slug}")
        return self._project_from_mod(payload.get("data", {}))

    def get_project_versions(self, project_id_or_slug: str) -> list[ProviderVersion]:
        files = self.client.get_files(int(project_id_or_slug), page_size=50)
        return [self._version_from_file(file_payload) for file_payload in files]

    def get_version(self, version_id: str) -> ProviderVersion:
        raise NotImplementedError("CurseForge requires project ID plus file ID for version lookup")

    def get_project_dependencies(self, project_id_or_slug: str) -> list[ProviderDependency]:
        versions = self.get_project_versions(project_id_or_slug)
        return [dependency for version in versions for dependency in version.dependencies]

    @staticmethod
    def _project_from_mod(item: dict[str, Any]) -> ProviderProject:
        links = item.get("links") or {}
        return ProviderProject(
            provider="curseforge",
            provider_project_id=str(item.get("id") or ""),
            slug=str(item.get("slug") or ""),
            title=str(item.get("name") or ""),
            project_type="mod",
            downloads=int(item.get("downloadCount") or 0),
            source_url=links.get("sourceUrl"),
            issues_url=links.get("issuesUrl"),
            website_url=links.get("websiteUrl"),
            game_versions=[
                str(version.get("gameVersion"))
                for version in item.get("latestFilesIndexes", [])
                if version.get("gameVersion")
            ],
            raw_metadata=item,
        )

    @staticmethod
    def _version_from_file(item: dict[str, Any]) -> ProviderVersion:
        return ProviderVersion(
            provider="curseforge",
            provider_project_id=str(item.get("modId") or ""),
            provider_version_id=str(item.get("id") or ""),
            version_number=str(item.get("displayName") or item.get("fileName") or ""),
            publication_date=item.get("fileDate"),
            game_versions=[str(version) for version in item.get("gameVersions", [])],
            raw_metadata=item,
        )
