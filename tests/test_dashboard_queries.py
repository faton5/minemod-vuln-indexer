from pathlib import Path

from dashboard.data import queries
from minemod_audit.ai.cache import GeminiAnalysisCache
from minemod_audit.ai.schemas import GeminiSecurityAnalysis
from minemod_audit.database import DataStore
from minemod_audit.models import (
    AffectedModpack,
    CrawlerEvent,
    Finding,
    Modpack,
    ModpackComponent,
    ModpackRelease,
    ModProject,
    RecentSecurityFixCandidate,
    SourceType,
    Vulnerability,
)
from minemod_audit.providers.base import ProviderProject


def seed_dashboard_database(database: Path) -> None:
    store = DataStore(database)
    store.replace_models(
        "mods",
        [
            ModProject(
                project_id="modrinth:AABBCCDD",
                provider="modrinth",
                provider_project_id="AABBCCDD",
                name="Example Mod",
                slug="example-mod",
                download_count=1200,
                categories=["fabric"],
                latest_versions=["1.20.1"],
                source_url="https://github.com/example/mod",
            )
        ],
        key=lambda item: str(item.project_id),
    )
    store.replace_models(
        "provider_projects",
        [
            ProviderProject(
                provider="modrinth",
                provider_project_id="AABBCCDD",
                slug="example-mod",
                title="Example Mod",
                project_type="mod",
                downloads=1200,
                raw_metadata={"api_key": "secret-value"},
            )
        ],
        key=lambda item: f"{item.provider}:{item.provider_project_id}",
    )
    store.replace_models(
        "modpacks",
        [
            Modpack(
                project_id="modrinth:PACK0001",
                provider="modrinth",
                provider_project_id="PACK0001",
                name="Example Pack",
                slug="example-pack",
                download_count=500,
            )
        ],
        key=lambda item: str(item.project_id),
    )
    store.replace_models(
        "modpack_releases",
        [
            ModpackRelease(
                file_id="modrinth:VER00001",
                modpack_project_id="modrinth:PACK0001",
                display_name="1.0.0",
                minecraft_version="1.20.1",
                loader="fabric",
            )
        ],
        key=lambda item: str(item.file_id),
    )
    store.replace_models(
        "modpack_components",
        [
            ModpackComponent(
                modpack_file_id="modrinth:VER00001",
                mod_project_id="modrinth:AABBCCDD",
                mod_file_id="modrinth:MODVER01",
                mod_name="Example Mod",
                mod_version="1.2.3",
            )
        ],
        key=lambda item: f"{item.modpack_file_id}:{item.mod_project_id}",
    )
    store.replace_models(
        "vulnerabilities",
        [
            Vulnerability(
                internal_id="GHSA-1",
                mod_project_id="modrinth:AABBCCDD",
                mod_name="Example Mod",
                title="Confirmed issue",
                source_type=SourceType.GHSA,
                source_url="https://github.com/advisories/GHSA-1",
                severity="high",
                impact_category="item_duplication",
                affected_versions=["<1.2.4"],
                fixed_versions=["1.2.4"],
                status="confirmed",
                confidence=100,
                requires_manual_review=False,
            ),
            Vulnerability(
                internal_id="candidate-1",
                mod_project_id="modrinth:AABBCCDD",
                mod_name="Example Mod",
                title="Candidate issue",
                source_type=SourceType.ISSUE,
                source_url="https://github.com/example/mod/issues/1",
                severity="unknown",
                status="candidate",
                confidence=20,
                requires_manual_review=True,
            ),
        ],
        key=lambda item: item.internal_id,
    )
    store.replace_models(
        "findings",
        [
            Finding(
                mod_name="Example Mod",
                mod_version="1.2.3",
                modpack_name="Example Pack",
                modpack_release="1.0.0",
                minecraft_version="1.20.1",
                loader="fabric",
                affected_range="<1.2.4",
                fixed_versions=["1.2.4"],
                impact_category="item_duplication",
                confidence=100,
                status="confirmed",
                source_urls=["https://github.com/advisories/GHSA-1"],
            )
        ],
        key=lambda item: f"{item.modpack_name}:{item.mod_name}",
    )


def test_overview_stats_empty_database_path() -> None:
    stats = queries.overview_stats(Path("missing-dashboard-test.sqlite"))

    assert stats.mods == 0
    assert stats.findings == 0


def test_overview_stats_separates_confirmed_and_candidate(tmp_path: Path) -> None:
    database = tmp_path / "dashboard.sqlite"
    seed_dashboard_database(database)

    stats = queries.overview_stats(database)

    assert stats.mods == 1
    assert stats.modpacks == 1
    assert stats.confirmed_vulnerabilities == 1
    assert stats.candidate_vulnerabilities == 1
    assert stats.manual_review == 1


def test_filters_and_pagination(tmp_path: Path) -> None:
    database = tmp_path / "dashboard.sqlite"
    seed_dashboard_database(database)
    rows = queries.load_records(database, "mods")

    filtered = queries.filter_records(
        rows,
        search="example",
        provider="modrinth",
        loader="fabric",
        minecraft_version="1.20.1",
        min_downloads=1000,
    )

    assert len(filtered) == 1
    assert queries.paginate(filtered, page=1, page_size=1) == filtered
    assert queries.paginate(filtered, page=2, page_size=1) == []


def test_exports_respect_filtered_rows(tmp_path: Path) -> None:
    database = tmp_path / "dashboard.sqlite"
    seed_dashboard_database(database)
    rows = queries.load_records(database, "findings")

    assert "Example Mod" in queries.export_csv(rows)
    assert '"mod_name": "Example Mod"' in queries.export_json(rows)
    assert "[CONFIRMED] Example Mod 1.2.3" in queries.export_findings_markdown(rows)


def test_sensitive_values_are_redacted(tmp_path: Path) -> None:
    database = tmp_path / "dashboard.sqlite"
    seed_dashboard_database(database)

    rows = queries.load_records(database, "provider_projects")

    assert rows[0]["raw_metadata"]["api_key"] == "<redacted>"


def test_load_records_refreshes_after_database_changes(tmp_path: Path) -> None:
    database = tmp_path / "dashboard.sqlite"
    seed_dashboard_database(database)

    assert len(queries.load_records(database, "mods")) == 1

    store = DataStore(database)
    store.append_models(
        "mods",
        [
            ModProject(
                project_id="curseforge:1234",
                provider="curseforge",
                provider_project_id="1234",
                name="Second Mod",
                slug="second-mod",
                download_count=10,
            )
        ],
        key=lambda item: str(item.project_id),
    )

    rows = queries.load_records(database, "mods")

    assert len(rows) == 2


def test_dashboard_counts_and_ai_usage(tmp_path: Path) -> None:
    database = tmp_path / "dashboard.sqlite"
    seed_dashboard_database(database)
    cache = GeminiAnalysisCache(DataStore(database))
    analysis = GeminiSecurityAnalysis(
        verdict="insufficient_evidence",
        confidence=30,
        category="unknown",
        affected_version_confidence=50,
        fixed_version_confidence=50,
        public_information_level="none",
        requires_manual_review=True,
        concise_explanation="Not enough public evidence.",
    )
    cache.put(
        evidence_hash="hash-1",
        candidate_id="candidate-1",
        model="gemini-test",
        prompt_version="security-triage-v1",
        schema_version="schema-v1",
        analysis=analysis,
        input_token_count=100,
        output_token_count=20,
        status="valid",
    )

    counts = queries.record_kind_counts(database)
    usage = queries.ai_usage_stats(database)

    assert counts["mods"] == 1
    assert counts["gemini_analysis_cache"] == 1
    assert usage["cached_analyses"] == 1
    assert usage["input_tokens"] == 100
    assert usage["output_tokens"] == 20


def test_security_candidate_rows_exposure_status(tmp_path: Path) -> None:
    database = tmp_path / "dashboard.sqlite"
    store = DataStore(database)
    store.replace_models(
        "recent_security_fix_candidates",
        [
            RecentSecurityFixCandidate(
                candidate_id="candidate-1",
                mod_name="Example Mod",
                provider="curseforge",
                provider_project_id="1234",
                old_version="1.0.0",
                fixed_version="1.0.1",
                changelog_excerpt="Fix packet validation.",
                patch_summary="Added server-side validation.",
                potential_impact="Possible packet validation issue.",
                confidence=70,
                category="likely_security_fix",
                affected_modpacks=[
                    AffectedModpack(
                        modpack="Example Pack",
                        modpack_release="2.0.0",
                        installed_version="1.0.0",
                        fixed_version="1.0.1",
                        same_minecraft_loader=True,
                        latest_pack_release=True,
                    )
                ],
            )
        ],
        key=lambda item: item.candidate_id,
    )

    rows = queries.security_candidate_rows(database)

    assert rows[0]["affected_modpacks_count"] == 1
    assert rows[0]["latest_affected_modpacks"] == 1
    assert rows[0]["exposure_status"] == "latest_pack_still_affected"
    assert rows[0]["attention_level"] == "high"
    assert rows[0]["dashboard_actionable"] is True
    assert rows[0]["modpack_status"] == "1 latest release(s) still affected"
    assert rows[0]["fix_status"] == "Fix identified: 1.0.0 -> 1.0.1"


def test_crawler_events_can_be_filtered_by_candidate(tmp_path: Path) -> None:
    database = tmp_path / "dashboard.sqlite"
    store = DataStore(database)
    store.append_models(
        "crawler_events",
        [
            CrawlerEvent(
                event_id="event-1",
                run_id="run-1",
                stage="recent_security_fixes.candidate",
                message="Example Mod selected.",
                created_at="2026-07-02T10:00:00+00:00",
                candidate_id="candidate-1",
                mod_name="Example Mod",
                data={"ai_verdict": "interesting_security_fix"},
            ),
            CrawlerEvent(
                event_id="event-2",
                run_id="run-1",
                stage="recent_security_fixes.candidate",
                message="Other Mod selected.",
                created_at="2026-07-02T11:00:00+00:00",
                candidate_id="candidate-2",
                mod_name="Other Mod",
            ),
        ],
        key=lambda item: item.event_id,
    )

    events = queries.crawler_events(database, candidate_id="candidate-1")

    assert len(events) == 1
    assert events[0]["mod_name"] == "Example Mod"
    assert events[0]["data"]["ai_verdict"] == "interesting_security_fix"


def test_ai_normal_bugfix_deprioritizes_manual_review_noise(tmp_path: Path) -> None:
    database = tmp_path / "dashboard.sqlite"
    store = DataStore(database)
    store.replace_models(
        "recent_security_fix_candidates",
        [
            RecentSecurityFixCandidate(
                candidate_id="candidate-normal",
                mod_name="Noise Mod",
                provider="curseforge",
                provider_project_id="4567",
                old_version="1.0.0",
                fixed_version="1.0.1",
                changelog_excerpt="Improve updater networking.",
                patch_summary="No linked diff available",
                potential_impact="Standard bug fix.",
                confidence=70,
                category="interesting_bugfix",
                ai_verdict="normal_bugfix",
                ai_confidence=85,
                ai_status="valid",
                ai_concise_explanation="No security-relevant behavior was identified.",
            )
        ],
        key=lambda item: item.candidate_id,
    )

    rows = queries.security_candidate_rows(database)

    assert rows[0]["attention_level"] == "low"
    assert rows[0]["dashboard_actionable"] is False
    assert rows[0]["review_action"] == "Do not spend time unless new evidence appears."


def test_ai_insufficient_evidence_without_exposure_is_low_priority(tmp_path: Path) -> None:
    database = tmp_path / "dashboard.sqlite"
    store = DataStore(database)
    store.replace_models(
        "recent_security_fix_candidates",
        [
            RecentSecurityFixCandidate(
                candidate_id="candidate-insufficient",
                mod_name="Unclear Mod",
                provider="curseforge",
                provider_project_id="8910",
                old_version="1.0.0",
                fixed_version="1.0.1",
                changelog_excerpt="Fix dupe-like behavior.",
                patch_summary="No linked diff available",
                potential_impact="Maybe duplication, not enough evidence.",
                confidence=65,
                category="interesting_bugfix",
                ai_verdict="insufficient_evidence",
                ai_confidence=40,
                ai_status="valid",
            )
        ],
        key=lambda item: item.candidate_id,
    )

    rows = queries.security_candidate_rows(database)

    assert rows[0]["attention_level"] == "low"
    assert rows[0]["dashboard_actionable"] is False
