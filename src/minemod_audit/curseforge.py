from pathlib import Path
from typing import Any

import httpx

from minemod_audit.http_client import HttpClient
from minemod_audit.manifest import parse_manifest_json
from minemod_audit.models import Modpack, ModpackComponent, ModpackRelease, ModProject

MINECRAFT_GAME_ID = 432
SORT_TOTAL_DOWNLOADS = 6
SORT_LAST_UPDATED = 3
SORT_DESCENDING = "desc"


class CurseForgeClient:
    def __init__(
        self,
        *,
        api_key: str,
        cache_directory: Path,
        timeout_seconds: float,
        offline: bool = False,
        refresh: bool = False,
    ) -> None:
        self.http = HttpClient(
            base_url="https://api.curseforge.com",
            headers={"Accept": "application/json", "x-api-key": api_key},
            cache_directory=cache_directory / "curseforge",
            timeout_seconds=timeout_seconds,
            offline=offline,
            refresh=refresh,
        )
        self._mod_cache: dict[int, dict[str, Any]] = {}
        self._file_cache: dict[tuple[int, int], dict[str, Any]] = {}

    def close(self) -> None:
        self.http.close()

    def _search(
        self,
        *,
        class_id: int,
        limit: int,
        extra: dict[str, Any] | None = None,
    ) -> list[dict[str, Any]]:
        collected: list[dict[str, Any]] = []
        index = 0
        while len(collected) < limit:
            page_size = min(50, limit - len(collected))
            params: dict[str, Any] = {
                "gameId": MINECRAFT_GAME_ID,
                "classId": class_id,
                "sortField": SORT_TOTAL_DOWNLOADS,
                "sortOrder": SORT_DESCENDING,
                "index": index,
                "pageSize": page_size,
            }
            if extra:
                params.update(extra)
            payload = self.http.get_json("/v1/mods/search", params=params)
            page = list(payload.get("data", []))
            collected.extend(page)
            if len(page) < page_size:
                break
            index += page_size
        return collected[:limit]

    def resolve_class_id(self, wanted_slug: str) -> int:
        payload = self.http.get_json("/v1/categories", params={"gameId": MINECRAFT_GAME_ID})
        for category in payload.get("data", []):
            slug = str(category.get("slug") or "").lower()
            if slug == wanted_slug:
                raw_class_id = category.get("classId") or category.get("id")
                if raw_class_id is None:
                    break
                return int(raw_class_id)
        raise LookupError(f"CurseForge class not found for slug {wanted_slug!r}")

    def collect_mods(self, *, limit: int) -> list[ModProject]:
        class_id = self.resolve_class_id("mc-mods")
        return [self._mod_from_api(item) for item in self._search(class_id=class_id, limit=limit)]

    def collect_recent_popular_mods(self, *, limit: int) -> list[ModProject]:
        return self.collect_mods(limit=limit)

    def collect_modpacks(
        self,
        *,
        limit: int,
        minecraft_version: str | None = None,
    ) -> list[Modpack]:
        class_id = self.resolve_class_id("modpacks")
        extra = {"gameVersion": minecraft_version} if minecraft_version else None
        return [
            self._modpack_from_api(item)
            for item in self._search(class_id=class_id, limit=limit, extra=extra)
        ]

    def get_files(self, project_id: int, *, page_size: int) -> list[dict[str, Any]]:
        payload = self.http.get_json(
            f"/v1/mods/{project_id}/files",
            params={"pageSize": page_size, "index": 0},
        )
        return list(payload.get("data", []))

    def get_file(self, project_id: int, file_id: int) -> dict[str, Any]:
        cache_key = (project_id, file_id)
        if cache_key in self._file_cache:
            return self._file_cache[cache_key]
        payload = self.http.get_json(f"/v1/mods/{project_id}/files/{file_id}")
        file_payload = dict(payload.get("data", {}))
        self._file_cache[cache_key] = file_payload
        return file_payload

    def get_file_changelog(self, project_id: int, file_id: int) -> str:
        payload = self.http.get_json(f"/v1/mods/{project_id}/files/{file_id}/changelog")
        data = payload.get("data")
        return str(data or "")

    def get_mod(self, project_id: int) -> dict[str, Any]:
        if project_id in self._mod_cache:
            return self._mod_cache[project_id]
        payload = self.http.get_json(f"/v1/mods/{project_id}")
        mod_payload = dict(payload.get("data", {}))
        self._mod_cache[project_id] = mod_payload
        return mod_payload

    def get_download_url(self, project_id: int, file_id: int) -> str | None:
        payload = self.http.get_json(f"/v1/mods/{project_id}/files/{file_id}/download-url")
        data = payload.get("data")
        return str(data) if data else None

    def index_modpack_release(
        self,
        *,
        modpack: Modpack,
        file_payload: dict[str, Any],
    ) -> tuple[ModpackRelease, list[ModpackComponent]]:
        file_id = int(file_payload["id"])
        release = ModpackRelease(
            file_id=f"curseforge:{file_id}",
            modpack_project_id=modpack.project_id,
            display_name=str(
                file_payload.get("displayName") or file_payload.get("fileName") or file_id
            ),
            release_date=file_payload.get("fileDate"),
            download_url=None,
        )
        curseforge_project_id = int(modpack.provider_project_id or modpack.project_id)
        try:
            download_url = self.get_download_url(curseforge_project_id, file_id)
        except httpx.HTTPStatusError as exc:
            release.unresolved_reason = f"download URL unavailable: HTTP {exc.response.status_code}"
            return release, []
        if not download_url:
            release.unresolved_reason = "download URL unavailable"
            return release, []
        release.download_url = download_url

        try:
            response = httpx.get(download_url, timeout=60)
            response.raise_for_status()
        except httpx.HTTPError as exc:
            release.unresolved_reason = f"download failed: {exc.__class__.__name__}"
            return release, []

        import hashlib
        import io
        import json
        import zipfile

        payload = response.content
        release.sha256 = hashlib.sha256(payload).hexdigest()
        try:
            with (
                zipfile.ZipFile(io.BytesIO(payload)) as archive,
                archive.open("manifest.json") as handle,
            ):
                manifest = json.loads(handle.read().decode("utf-8"))
        except (KeyError, zipfile.BadZipFile, json.JSONDecodeError) as exc:
            release.unresolved_reason = f"manifest unavailable: {exc.__class__.__name__}"
            return release, []

        parsed = parse_manifest_json(manifest)
        release.minecraft_version = parsed.minecraft_version
        release.loader = parsed.loader
        components = []
        for component in parsed.components:
            project_id = int(component.project_id)
            component_file_id = int(component.file_id)
            mod_payload = self.get_mod(project_id)
            component_file = self.get_file(project_id, component_file_id)
            links = mod_payload.get("links") or {}
            components.append(
                ModpackComponent(
                    modpack_file_id=f"curseforge:{file_id}",
                    mod_project_id=f"curseforge:{project_id}",
                    mod_file_id=f"curseforge:{component_file_id}",
                    provider="curseforge",
                    provider_project_id=str(project_id),
                    provider_version_id=str(component_file_id),
                    mod_name=str(mod_payload.get("name") or ""),
                    mod_version=str(
                        component_file.get("displayName")
                        or component_file.get("fileName")
                        or component_file_id
                    ),
                    filename=component_file.get("fileName"),
                    hashes=_file_hashes(component_file),
                    loaders=[parsed.loader] if parsed.loader else [],
                    minecraft_versions=[parsed.minecraft_version]
                    if parsed.minecraft_version
                    else [],
                    source_url=links.get("sourceUrl"),
                    resolution_status="resolved",
                    requires_manual_review=False,
                    required=component.required,
                )
            )
        return release, components

    @staticmethod
    def _mod_from_api(item: dict[str, Any]) -> ModProject:
        links = item.get("links") or {}
        latest_files_indexes = item.get("latestFilesIndexes") or []
        return ModProject(
            project_id=int(item["id"]),
            name=str(item.get("name") or ""),
            slug=str(item.get("slug") or ""),
            authors=[
                str(author.get("name")) for author in item.get("authors", []) if author.get("name")
            ],
            download_count=int(item.get("downloadCount") or 0),
            date_modified=item.get("dateModified"),
            class_id=item.get("classId"),
            primary_category_id=item.get("primaryCategoryId"),
            source_url=links.get("sourceUrl"),
            issues_url=links.get("issuesUrl"),
            website_url=links.get("websiteUrl"),
            main_file_id=item.get("mainFileId"),
            categories=[
                str(category.get("name"))
                for category in item.get("categories", [])
                if category.get("name")
            ],
            latest_versions=[
                str(version.get("gameVersion"))
                for version in latest_files_indexes
                if version.get("gameVersion")
            ],
            raw=item,
        )

    @staticmethod
    def _modpack_from_api(item: dict[str, Any]) -> Modpack:
        return Modpack(
            project_id=f"curseforge:{item['id']}",
            provider="curseforge",
            provider_project_id=str(item["id"]),
            name=str(item.get("name") or ""),
            slug=str(item.get("slug") or ""),
            download_count=int(item.get("downloadCount") or 0),
        )


def _file_hashes(file_payload: dict[str, Any]) -> dict[str, str]:
    algorithm_names = {
        1: "sha1",
        2: "md5",
    }
    hashes: dict[str, str] = {}
    for item in file_payload.get("hashes", []):
        if not isinstance(item, dict):
            continue
        value = item.get("value")
        if not value:
            continue
        raw_algorithm = item.get("algo")
        algorithm = raw_algorithm if isinstance(raw_algorithm, int) else None
        key = algorithm_names.get(algorithm, str(algorithm)) if algorithm is not None else "hash"
        hashes[key] = str(value)
    return hashes
