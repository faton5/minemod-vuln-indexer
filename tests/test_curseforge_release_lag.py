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


def _manifest_archive(manifest: dict[str, Any]) -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        archive.writestr("manifest.json", json.dumps(manifest))
    return buffer.getvalue()
