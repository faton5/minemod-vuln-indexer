from __future__ import annotations

from pathlib import Path

import pytest
from pydantic import ValidationError

from minemod_audit.ai.cache import GeminiAnalysisCache
from minemod_audit.ai.evidence import build_evidence_bundle, evidence_hash
from minemod_audit.ai.gemini_client import GeminiRunConfig, GeminiSecurityAnalyzer
from minemod_audit.ai.schemas import GeminiSecurityAnalysis
from minemod_audit.config import Settings
from minemod_audit.database import DataStore
from minemod_audit.models import AffectedModpack, RecentSecurityFixCandidate


class FakeGeminiClient:
    def __init__(self, analysis: GeminiSecurityAnalysis) -> None:
        self.analysis = analysis
        self.calls = 0

    def analyze(
        self,
        *,
        model: str,
        system_prompt: str,
        user_payload: str,
        max_output_tokens: int,
    ) -> tuple[GeminiSecurityAnalysis, int, int]:
        del model, system_prompt, user_payload, max_output_tokens
        self.calls += 1
        return self.analysis, 123, 45


def make_candidate(**updates: object) -> RecentSecurityFixCandidate:
    payload: dict[str, object] = {
        "candidate_id": "candidate-1",
        "mod_name": "FTB Library",
        "repository": "https://github.com/FTBTeam/FTB-Library",
        "provider": "curseforge",
        "provider_project_id": "404465",
        "old_file_id": "curseforge:6819020",
        "new_file_id": "curseforge:6819021",
        "old_version": "2101.1.31",
        "fixed_version": "2101.1.32",
        "minecraft_version": "1.21.1",
        "loader": "neoforge",
        "release_date": "2026-01-01T00:00:00Z",
        "changelog_excerpt": "NBT edit response validation fix",
        "pull_request_url": "https://github.com/FTBTeam/FTB-Library/pull/123",
        "commit_url": "https://github.com/FTBTeam/FTB-Library/commit/abc1234",
        "changed_files": ["EditNBTResponsePacket.java"],
        "patch_summary": (
            "+ currentlyEditing session state\n"
            "+ reject unsolicited NBT edit response\n"
            "+ compare client response with pending server request"
        ),
        "potential_impact": "Possible server-side trust boundary issue fixed publicly.",
        "public_exploit_information": "technical_description",
        "confidence": 70,
        "category": "likely_security_fix",
        "affected_modpacks": [
            AffectedModpack(
                modpack="All the Mods 10",
                modpack_release="2.0",
                installed_version="2101.1.31",
                fixed_version="2101.1.32",
                same_minecraft_loader=True,
                latest_pack_release=True,
                days_since_fix=5,
                download_count=1000,
            )
        ],
        "requires_manual_review": True,
    }
    payload.update(updates)
    return RecentSecurityFixCandidate.model_validate(payload)


def make_analysis(**updates: object) -> GeminiSecurityAnalysis:
    payload: dict[str, object] = {
        "verdict": "probable_exploitable_bug",
        "confidence": 72,
        "category": "nbt_validation",
        "root_cause": "Client NBT edit response accepted without enough session validation.",
        "previous_behavior": (
            "A client response could be processed without matching a pending edit."
        ),
        "added_protection": "Server checks currentlyEditing before accepting the response.",
        "potential_impact": "Possible unauthorized NBT state change.",
        "attacker_prerequisites": ["Player can send the affected client response."],
        "affected_version_confidence": 90,
        "fixed_version_confidence": 90,
        "public_information_level": "technical_description",
        "evidence_ids": ["changelog", "patch_summary"],
        "contradictions": [],
        "missing_information": [],
        "requires_manual_review": True,
        "concise_explanation": "The diff adds session-state validation for NBT edit responses.",
    }
    payload.update(updates)
    return GeminiSecurityAnalysis.model_validate(payload)


def make_settings(tmp_path: Path, *, enabled: bool = True) -> Settings:
    settings = Settings()
    settings.database = tmp_path / "db.sqlite"
    settings.gemini_ai_enabled = enabled
    settings.gemini_api_key = "local-test-key" if enabled else None
    settings.gemini_max_candidates_per_run = 20
    settings.gemini_max_review_calls_per_run = 3
    return settings


def test_bundle_hash_is_stable_and_changes_with_content() -> None:
    candidate = make_candidate()
    bundle = build_evidence_bundle(candidate, max_input_chars=30_000)

    assert evidence_hash(bundle, model="gemini-test", prompt_version="v1") == evidence_hash(
        build_evidence_bundle(candidate, max_input_chars=30_000),
        model="gemini-test",
        prompt_version="v1",
    )

    changed = build_evidence_bundle(
        make_candidate(changelog_excerpt="different NBT fix"),
        max_input_chars=30_000,
    )
    assert evidence_hash(bundle, model="gemini-test", prompt_version="v1") != evidence_hash(
        changed,
        model="gemini-test",
        prompt_version="v1",
    )


def test_cache_hit_avoids_second_gemini_call(tmp_path: Path) -> None:
    settings = make_settings(tmp_path)
    store = DataStore(settings.database)
    cache = GeminiAnalysisCache(store)
    client = FakeGeminiClient(make_analysis())
    analyzer = GeminiSecurityAnalyzer(settings=settings, cache=cache, client=client)
    candidate = make_candidate()

    first = analyzer.analyze_candidate(candidate, build_evidence_bundle(candidate))
    second = analyzer.analyze_candidate(candidate, build_evidence_bundle(candidate))

    assert client.calls == 1
    assert first.cache_hit is False
    assert second.cache_hit is True
    assert second.analysis is not None
    assert second.analysis.verdict == "probable_exploitable_bug"


def test_invalid_evidence_id_is_rejected(tmp_path: Path) -> None:
    settings = make_settings(tmp_path)
    analyzer = GeminiSecurityAnalyzer(
        settings=settings,
        cache=GeminiAnalysisCache(DataStore(settings.database)),
        client=FakeGeminiClient(make_analysis(evidence_ids=["unknown-evidence"])),
    )
    candidate = make_candidate()

    result = analyzer.analyze_candidate(candidate, build_evidence_bundle(candidate))

    assert result.status == "invalid"
    assert "unknown evidence_id" in (result.error or "")


def test_invented_url_is_rejected(tmp_path: Path) -> None:
    settings = make_settings(tmp_path)
    analyzer = GeminiSecurityAnalyzer(
        settings=settings,
        cache=GeminiAnalysisCache(DataStore(settings.database)),
        client=FakeGeminiClient(
            make_analysis(concise_explanation="See https://example.invalid/fake for details.")
        ),
    )
    candidate = make_candidate()

    result = analyzer.analyze_candidate(candidate, build_evidence_bundle(candidate))

    assert result.status == "invalid"
    assert "invented URL" in (result.error or "")


def test_disabled_or_missing_key_does_not_call_gemini(tmp_path: Path) -> None:
    settings = make_settings(tmp_path, enabled=False)
    client = FakeGeminiClient(make_analysis())
    analyzer = GeminiSecurityAnalyzer(
        settings=settings,
        cache=GeminiAnalysisCache(DataStore(settings.database)),
        client=client,
    )
    candidate = make_candidate()

    result = analyzer.analyze_candidate(candidate, build_evidence_bundle(candidate))

    assert client.calls == 0
    assert result.status == "skipped"
    assert "disabled" in (result.error or "")


def test_candidate_limit_is_enforced(tmp_path: Path) -> None:
    settings = make_settings(tmp_path)
    client = FakeGeminiClient(make_analysis())
    analyzer = GeminiSecurityAnalyzer(
        settings=settings,
        cache=GeminiAnalysisCache(DataStore(settings.database)),
        client=client,
    )
    candidates = [
        make_candidate(candidate_id=f"candidate-{index}", provider_project_id=str(index))
        for index in range(3)
    ]

    analyzed = analyzer.analyze_candidates(
        candidates,
        config=GeminiRunConfig(max_candidates=2, max_review_calls=0),
    )

    assert client.calls == 2
    assert len(analyzed) == 3
    assert analyzed[2].ai_verdict is None


def test_visual_only_candidate_is_not_sent_to_gemini(tmp_path: Path) -> None:
    settings = make_settings(tmp_path)
    client = FakeGeminiClient(make_analysis())
    analyzer = GeminiSecurityAnalyzer(
        settings=settings,
        cache=GeminiAnalysisCache(DataStore(settings.database)),
        client=client,
    )
    candidate = make_candidate(
        changelog_excerpt="Texture and shader visual fix",
        patch_summary="Changed files: renderer texture",
        old_version="",
    )

    result = analyzer.analyze_candidate(candidate, build_evidence_bundle(candidate))

    assert client.calls == 0
    assert result.status == "skipped"


def test_truncation_marks_bundle() -> None:
    candidate = make_candidate(changelog_excerpt="packet validation " * 1000)

    bundle = build_evidence_bundle(candidate, max_input_chars=500)

    assert bundle.truncated is True
    assert len(bundle.model_dump_json()) <= 900


def test_confidence_validation() -> None:
    with pytest.raises(ValidationError):
        make_analysis(confidence=101)
