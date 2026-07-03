import io
import json
import zipfile
from typing import Any

import httpx
from pytest import MonkeyPatch

from minemod_audit.curseforge import CurseForgeClient
from minemod_audit.models import Modpack


class FakeDownloadResponse:
    def __init__(self, content: bytes) -> None:
        self.content = content

    def raise_for_status(self) -> None:
        return None


class FakeCurseForgeSearchHttp:
    def __init__(self) -> None:
        self.search_params: list[dict[str, object]] = []

    def get_json(
        self,
        path: str,
        *,
        params: dict[str, object] | None = None,
    ) -> dict[str, object]:
        if path == "/v1/categories":
            return {"data": [{"slug": "mc-mods", "classId": 6}]}
        if path == "/v1/mods/search":
            self.search_params.append(dict(params or {}))
            return {
                "data": [
                    {
                        "id": 1,
                        "name": "Huge Mod",
                        "slug": "huge-mod",
                        "downloadCount": 50_000_000,
                    },
                    {
                        "id": 2,
                        "name": "Large Mod",
                        "slug": "large-mod",
                        "downloadCount": 10_000_000,
                    },
                ]
            }
        raise AssertionError(f"unexpected path {path}")


def test_recent_popular_curseforge_mods_start_from_total_downloads() -> None:
    client = CurseForgeClient.__new__(CurseForgeClient)
    fake_http = FakeCurseForgeSearchHttp()
    client.http = fake_http
    client._mod_cache = {}
    client._file_cache = {}

    mods = client.collect_recent_popular_mods(limit=2)

    assert [mod.name for mod in mods] == ["Huge Mod", "Large Mod"]
    assert fake_http.search_params[0]["sortField"] == 6


def test_curseforge_modpack_release_resolves_exact_component_metadata(
    monkeypatch: MonkeyPatch,
) -> None:
    client = CurseForgeClient.__new__(CurseForgeClient)
    manifest = {
        "minecraft": {
            "version": "1.21",
            "modLoaders": [{"id": "neoforge-21.0.0", "primary": True}],
        },
        "files": [{"projectID": 404465, "fileID": 6001, "required": True}],
    }
    archive_bytes = _manifest_archive(manifest)

    monkeypatch.setattr(
        httpx,
        "get",
        lambda *args, **kwargs: FakeDownloadResponse(archive_bytes),
    )
    monkeypatch.setattr(
        client, "get_download_url", lambda project_id, file_id: "https://cdn.invalid/pack.zip"
    )
    monkeypatch.setattr(
        client,
        "get_mod",
        lambda project_id: {
            "id": project_id,
            "name": "FTB Library",
            "slug": "ftb-library",
            "links": {"sourceUrl": "https://github.com/FTBTeam/FTB-Library"},
        },
    )
    monkeypatch.setattr(
        client,
        "get_file",
        lambda project_id, file_id: {
            "id": file_id,
            "modId": project_id,
            "displayName": "2101.1.14",
            "fileName": "ftb-library-neoforge-2101.1.14.jar",
            "fileDate": "2026-06-10T00:00:00Z",
            "gameVersions": ["1.21", "NeoForge"],
            "hashes": [{"algo": 1, "value": "sha1-value"}],
        },
    )

    release, components = client.index_modpack_release(
        modpack=Modpack(project_id=1234, name="All the Mods 10", slug="atm10"),
        file_payload={"id": 5001, "displayName": "ATM10 1.0.0"},
    )

    assert release.minecraft_version == "1.21"
    assert release.loader == "neoforge"
    assert len(components) == 1
    component = components[0]
    assert component.mod_project_id == "curseforge:404465"
    assert component.mod_file_id == "curseforge:6001"
    assert component.provider == "curseforge"
    assert component.provider_project_id == "404465"
    assert component.provider_version_id == "6001"
    assert component.mod_name == "FTB Library"
    assert component.mod_version == "2101.1.14"
    assert component.filename == "ftb-library-neoforge-2101.1.14.jar"
    assert component.hashes == {"sha1": "sha1-value"}
    assert component.source_url == "https://github.com/FTBTeam/FTB-Library"
    assert component.resolution_status == "resolved"
    assert component.requires_manual_review is False


def test_curseforge_modpack_release_continues_when_download_url_is_forbidden(
    monkeypatch: MonkeyPatch,
) -> None:
    client = CurseForgeClient.__new__(CurseForgeClient)
    request = httpx.Request("GET", "https://api.curseforge.com/v1/download-url")
    response = httpx.Response(403, request=request)

    def forbidden_download_url(project_id: int, file_id: int) -> str | None:
        del project_id, file_id
        raise httpx.HTTPStatusError("Forbidden", request=request, response=response)

    monkeypatch.setattr(client, "get_download_url", forbidden_download_url)

    release, components = client.index_modpack_release(
        modpack=Modpack(
            project_id="curseforge:1234",
            provider="curseforge",
            provider_project_id="1234",
            name="All the Mods 10",
            slug="atm10",
        ),
        file_payload={"id": 5001, "displayName": "ATM10 1.0.0"},
    )

    assert components == []
    assert release.unresolved_reason == "download URL unavailable: HTTP 403"


def _manifest_archive(manifest: dict[str, Any]) -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        archive.writestr("manifest.json", json.dumps(manifest))
    return buffer.getvalue()
