import json
import time
from typing import Any

from minemod_audit import __version__
from minemod_audit.config import Settings
from minemod_audit.http_client import HttpClient
from minemod_audit.providers.base import (
    ProviderDependency,
    ProviderFile,
    ProviderName,
    ProviderProject,
    ProviderStatus,
    ProviderVersion,
)

MAX_MODRINTH_PAGE_SIZE = 100


def build_modrinth_user_agent(version: str = __version__, contact_email: str | None = None) -> str:
    base = f"faton5/minemod-vuln-indexer/{version} (https://github.com/faton5/minemod-vuln-indexer"
    if contact_email and contact_email.strip():
        return f"{base}; {contact_email.strip()})"
    return f"{base})"


class ModrinthProvider:
    name: ProviderName = "modrinth"

    def __init__(
        self,
        settings: Settings,
        *,
        http: Any | None = None,
        page_size: int = MAX_MODRINTH_PAGE_SIZE,
        offline: bool = False,
        refresh: bool = False,
    ) -> None:
        self.settings = settings
        self.page_size = min(page_size, MAX_MODRINTH_PAGE_SIZE)
        self.requests_per_minute = settings.modrinth_requests_per_minute
        self._request_interval = 60.0 / max(1, self.requests_per_minute)
        self._last_request_at = 0.0
        self.http = http or HttpClient(
            base_url=settings.modrinth_base_url,
            headers={
                "Accept": "application/json",
                "User-Agent": build_modrinth_user_agent(
                    __version__,
                    settings.modrinth_contact_email,
                ),
            },
            cache_directory=settings.cache_directory / "modrinth",
            timeout_seconds=settings.timeout_seconds,
            offline=offline,
            refresh=refresh,
        )

    def close(self) -> None:
        self.http.close()

    def health_check(self) -> ProviderStatus:
        if not self.settings.modrinth_enabled:
            return ProviderStatus(
                name="Modrinth",
                status="disabled",
                priority=1,
                reason="Disabled by config",
            )
        try:
            self._get("/")
        except Exception as exc:  # noqa: BLE001
            return ProviderStatus(
                name="Modrinth",
                status="warning",
                priority=1,
                reason=f"Public API check failed: {exc.__class__.__name__}",
            )
        return ProviderStatus(
            name="Modrinth",
            status="enabled",
            priority=1,
            reason="Public API available",
        )

    def list_popular_mods(self, limit: int, offset: int = 0) -> list[ProviderProject]:
        return self._list_popular(project_type="mod", limit=limit, offset=offset)

    def list_popular_modpacks(self, limit: int, offset: int = 0) -> list[ProviderProject]:
        return self._list_popular(project_type="modpack", limit=limit, offset=offset)

    def get_project(self, project_id_or_slug: str) -> ProviderProject:
        payload = self._get(f"/project/{project_id_or_slug}")
        return self._project_from_payload(payload)

    def get_project_versions(self, project_id_or_slug: str) -> list[ProviderVersion]:
        payload = self._get(
            f"/project/{project_id_or_slug}/version",
            params={"include_changelog": "false"},
        )
        return [self._version_from_payload(item) for item in payload]

    def get_version(self, version_id: str) -> ProviderVersion:
        payload = self._get(f"/version/{version_id}")
        return self._version_from_payload(payload)

    def get_project_dependencies(self, project_id_or_slug: str) -> list[ProviderDependency]:
        payload = self._get(f"/project/{project_id_or_slug}/dependencies")
        raw_dependencies = payload.get("projects", []) if isinstance(payload, dict) else payload
        return [
            ProviderDependency(
                provider="modrinth",
                provider_project_id=str(item.get("id") or item.get("project_id") or ""),
                dependency_type=str(item.get("dependency_type") or "required"),
                raw_metadata=dict(item),
            )
            for item in raw_dependencies
        ]

    def rate_limit_status(self) -> dict[str, str] | None:
        return getattr(self.http, "last_rate_limit", None)

    def _list_popular(self, *, project_type: str, limit: int, offset: int) -> list[ProviderProject]:
        projects: list[ProviderProject] = []
        cursor = offset
        while len(projects) < limit:
            page_limit = min(self.page_size, limit - len(projects))
            payload = self._get(
                "/search",
                params={
                    "facets": json.dumps([[f"project_type:{project_type}"]], separators=(",", ":")),
                    "index": "downloads",
                    "limit": page_limit,
                    "offset": cursor,
                },
            )
            hits = [
                item for item in payload.get("hits", []) if item.get("project_type") == project_type
            ]
            projects.extend(self._project_from_payload(item) for item in hits)
            if len(hits) < page_limit:
                break
            cursor += page_limit
        return projects[:limit]

    def _get(self, path: str, *, params: dict[str, Any] | None = None) -> Any:
        self._throttle()
        return self.http.get_json(path, params=params)

    def _throttle(self) -> None:
        elapsed = time.monotonic() - self._last_request_at
        if self._last_request_at and elapsed < self._request_interval:
            time.sleep(self._request_interval - elapsed)
        self._last_request_at = time.monotonic()

    @staticmethod
    def _project_from_payload(item: dict[str, Any]) -> ProviderProject:
        project_id = item.get("id") or item.get("project_id")
        return ProviderProject(
            provider="modrinth",
            provider_project_id=str(project_id),
            slug=str(item.get("slug") or ""),
            title=str(item.get("title") or item.get("name") or ""),
            description=item.get("description"),
            project_type=str(item.get("project_type") or ""),
            downloads=int(item.get("downloads") or 0),
            source_url=item.get("source_url"),
            issues_url=item.get("issues_url"),
            website_url=item.get("wiki_url"),
            client_side=item.get("client_side"),
            server_side=item.get("server_side"),
            loaders=[str(loader) for loader in item.get("loaders", [])],
            game_versions=[str(version) for version in item.get("versions", [])],
            raw_metadata=item,
        )

    @staticmethod
    def _version_from_payload(item: dict[str, Any]) -> ProviderVersion:
        return ProviderVersion(
            provider="modrinth",
            provider_project_id=str(item.get("project_id") or ""),
            provider_version_id=str(item.get("id") or ""),
            version_number=str(item.get("version_number") or ""),
            publication_date=item.get("date_published"),
            loaders=[str(loader) for loader in item.get("loaders", [])],
            game_versions=[str(version) for version in item.get("game_versions", [])],
            dependencies=[
                ProviderDependency(
                    provider="modrinth",
                    provider_project_id=dependency.get("project_id"),
                    provider_version_id=dependency.get("version_id"),
                    dependency_type=str(dependency.get("dependency_type") or "required"),
                    raw_metadata=dict(dependency),
                )
                for dependency in item.get("dependencies", [])
            ],
            files=[
                ProviderFile(
                    filename=str(file_payload.get("filename") or ""),
                    url=file_payload.get("url"),
                    hashes={
                        str(key): str(value)
                        for key, value in (file_payload.get("hashes") or {}).items()
                    },
                    size=file_payload.get("size"),
                    primary=bool(file_payload.get("primary", False)),
                )
                for file_payload in item.get("files", [])
            ],
            raw_metadata=item,
        )
