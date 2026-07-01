from typing import Any

from pydantic import BaseModel


class ManifestComponent(BaseModel):
    project_id: int
    file_id: int
    required: bool = True


class ParsedManifest(BaseModel):
    minecraft_version: str | None
    loader: str | None
    components: list[ManifestComponent]


def _normalize_loader(loader_id: str | None) -> str | None:
    if not loader_id:
        return None
    return loader_id.split("-", maxsplit=1)[0].lower()


def parse_manifest_json(manifest: dict[str, Any]) -> ParsedManifest:
    minecraft = manifest.get("minecraft", {})
    loaders = minecraft.get("modLoaders", [])
    fallback_loader = loaders[0] if loaders else {}
    primary_loader = next(
        (loader for loader in loaders if loader.get("primary")),
        fallback_loader,
    )
    components = [
        ManifestComponent(
            project_id=int(item["projectID"]),
            file_id=int(item["fileID"]),
            required=bool(item.get("required", True)),
        )
        for item in manifest.get("files", [])
        if "projectID" in item and "fileID" in item
    ]
    return ParsedManifest(
        minecraft_version=minecraft.get("version"),
        loader=_normalize_loader(primary_loader.get("id")),
        components=components,
    )
