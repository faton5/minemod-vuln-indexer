from minemod_audit.models import SourceType
from minemod_audit.security import (
    classify_impact,
    confidence_for_source,
    deduplicate_vulnerabilities,
)


def test_classify_minecraft_item_duplication_impact() -> None:
    assert classify_impact("Fix item duplication with NBT payload replay") == "item_duplication"


def test_classify_rce_requires_standalone_term() -> None:
    assert classify_impact("Startup crash from resource pack rendering") == "other"
    assert classify_impact("Fix RCE in deserialization path") == "remote_code_execution"


def test_official_advisory_with_versions_has_high_confidence() -> None:
    assert confidence_for_source(SourceType.GHSA, has_version_range=True) == 100


def test_deduplicate_by_cve_ghsa_and_osv() -> None:
    items = [
        {"title": "A", "cve_id": "CVE-2024-0001", "ghsa_id": None, "osv_id": None},
        {"title": "B", "cve_id": "CVE-2024-0001", "ghsa_id": None, "osv_id": None},
        {"title": "C", "cve_id": None, "ghsa_id": "GHSA-abcd-efgh", "osv_id": None},
    ]

    deduped = deduplicate_vulnerabilities(items)

    assert [item["title"] for item in deduped] == ["A", "C"]
