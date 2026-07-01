from collections.abc import Iterable
from typing import Any

from minemod_audit.models import ImpactCategory, SourceType

_IMPACT_TERMS: list[tuple[str, tuple[str, ...]]] = [
    (
        ImpactCategory.REMOTE_CODE_EXECUTION.value,
        ("rce", "remote code execution", "objectinputstream", "deserialization"),
    ),
    (ImpactCategory.ITEM_DUPLICATION.value, ("dupe", "duplication", "duplicate")),
    (ImpactCategory.ITEM_CREATION.value, ("arbitrary item", "item creation", "creative item")),
    (ImpactCategory.INVENTORY_MODIFICATION.value, ("inventory", "container", "itemstack", "nbt")),
    (ImpactCategory.PERMISSION_BYPASS.value, ("permission bypass", "op bypass", "authorization")),
    (ImpactCategory.TELEPORTATION.value, ("teleport", "distance check")),
    (ImpactCategory.SERVER_CRASH.value, ("server crash", "crash server")),
    (ImpactCategory.DENIAL_OF_SERVICE.value, ("denial of service", "dos")),
    (ImpactCategory.INFORMATION_DISCLOSURE.value, ("information disclosure", "leak")),
]


def classify_impact(text: str) -> str:
    haystack = text.lower()
    for impact, terms in _IMPACT_TERMS:
        if any(term in haystack for term in terms):
            return impact
    return ImpactCategory.OTHER.value


def confidence_for_source(source_type: SourceType, *, has_version_range: bool = False) -> int:
    official_sources = {
        SourceType.GHSA,
        SourceType.REPOSITORY_ADVISORY,
        SourceType.OSV,
        SourceType.NVD,
    }
    if source_type in official_sources:
        return 100 if has_version_range else 90
    if source_type == SourceType.RELEASE:
        return 80
    if source_type in {SourceType.ISSUE, SourceType.PULL_REQUEST}:
        return 60
    if source_type == SourceType.COMMIT:
        return 40
    return 20


def _dedupe_key(item: dict[str, Any]) -> tuple[str, str]:
    for field in ("cve_id", "ghsa_id", "osv_id", "source_url"):
        value = item.get(field)
        if value:
            return field, str(value).lower()
    return "title", str(item.get("title", "")).lower()


def deduplicate_vulnerabilities(items: Iterable[dict[str, Any]]) -> list[dict[str, Any]]:
    seen: set[tuple[str, str]] = set()
    deduped: list[dict[str, Any]] = []
    for item in items:
        key = _dedupe_key(item)
        if key in seen:
            continue
        seen.add(key)
        deduped.append(item)
    return deduped
