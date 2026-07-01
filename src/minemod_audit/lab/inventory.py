from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class InventoryEntry:
    mod_id: str
    version: str
    source_path: Path | None = None


def normalize_inventory(entries: list[InventoryEntry]) -> list[InventoryEntry]:
    unique: dict[tuple[str, str], InventoryEntry] = {}
    for entry in entries:
        unique[(entry.mod_id.lower(), entry.version)] = entry
    return sorted(unique.values(), key=lambda item: (item.mod_id.lower(), item.version))
