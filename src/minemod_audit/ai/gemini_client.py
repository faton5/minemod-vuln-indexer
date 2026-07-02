from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Protocol

from minemod_audit.ai.cache import GeminiAnalysisCache
from minemod_audit.ai.evidence import (
    build_evidence_bundle,
    canonical_json,
    evidence_hash,
    urls_in_text,
)
from minemod_audit.ai.prompts import GEMINI_SECURITY_SYSTEM_PROMPT
from minemod_audit.ai.schemas import GeminiEvidenceBundle, GeminiSecurityAnalysis
from minemod_audit.config import Settings
from minemod_audit.models import RecentSecurityFixCandidate


class GeminiClient(Protocol):
    def analyze(
        self,
        *,
        model: str,
        system_prompt: str,
        user_payload: str,
        max_output_tokens: int,
    ) -> tuple[GeminiSecurityAnalysis, int, int]: ...


@dataclass(frozen=True)
class GeminiRunConfig:
    model: str | None = None
    review_model: str | None = None
    max_candidates: int | None = None
    max_review_calls: int | None = None
    refresh_cache: bool = False


@dataclass(frozen=True)
class GeminiAnalysisResult:
    candidate_id: str
    evidence_hash: str
    status: str
    analysis: GeminiSecurityAnalysis | None = None
    cache_hit: bool = False
    error: str | None = None
    input_tokens: int = 0
    output_tokens: int = 0
    analyzed_at: str | None = None


class GoogleGenAIClient:
    def __init__(self, api_key: str) -> None:
        from google import genai

        self.client = genai.Client(api_key=api_key)

    def analyze(
        self,
        *,
        model: str,
        system_prompt: str,
        user_payload: str,
        max_output_tokens: int,
    ) -> tuple[GeminiSecurityAnalysis, int, int]:
        from google.genai import types

        response = self.client.models.generate_content(
            model=model,
            contents=user_payload,
            config=types.GenerateContentConfig(
                system_instruction=system_prompt,
                response_mime_type="application/json",
                response_schema=GeminiSecurityAnalysis,
                max_output_tokens=max_output_tokens,
            ),
        )
        parsed = getattr(response, "parsed", None)
        if isinstance(parsed, GeminiSecurityAnalysis):
            analysis = parsed
        elif parsed is not None:
            analysis = GeminiSecurityAnalysis.model_validate(parsed)
        else:
            analysis = GeminiSecurityAnalysis.model_validate_json(str(response.text))
        usage = getattr(response, "usage_metadata", None)
        input_tokens = int(getattr(usage, "prompt_token_count", 0) or 0)
        output_tokens = int(getattr(usage, "candidates_token_count", 0) or 0)
        return analysis, input_tokens, output_tokens


class GeminiSecurityAnalyzer:
    def __init__(
        self,
        *,
        settings: Settings,
        cache: GeminiAnalysisCache,
        client: GeminiClient | None = None,
    ) -> None:
        self.settings = settings
        self.cache = cache
        self.client = client
        self.calls = 0
        self.cache_hits = 0
        self.input_tokens = 0
        self.output_tokens = 0

    def analyze_candidates(
        self,
        candidates: list[RecentSecurityFixCandidate],
        *,
        config: GeminiRunConfig | None = None,
    ) -> list[RecentSecurityFixCandidate]:
        run_config = config or GeminiRunConfig()
        max_candidates = run_config.max_candidates or self.settings.gemini_max_candidates_per_run
        analyzed: list[RecentSecurityFixCandidate] = []
        dedupe: dict[str, RecentSecurityFixCandidate] = {}
        used = 0
        for candidate in _prioritize_candidates(candidates):
            if used >= max_candidates:
                analyzed.append(candidate)
                continue
            bundle = build_evidence_bundle(
                candidate,
                max_input_chars=self.settings.gemini_max_input_chars,
            )
            key = _candidate_dedupe_key(candidate, bundle)
            reused = dedupe.get(key)
            if reused is not None and reused.ai_verdict:
                analyzed.append(_copy_ai_fields(candidate, reused))
                continue
            result = self.analyze_candidate(candidate, bundle, config=run_config)
            if result.analysis is None:
                analyzed.append(candidate)
                continue
            used += 1
            updated = _apply_analysis(candidate, result, self._model(run_config), run_config)
            dedupe[key] = updated
            analyzed.append(updated)
        return analyzed

    def analyze_candidate(
        self,
        candidate: RecentSecurityFixCandidate,
        evidence: GeminiEvidenceBundle,
        *,
        config: GeminiRunConfig | None = None,
    ) -> GeminiAnalysisResult:
        run_config = config or GeminiRunConfig()
        model = self._model(run_config)
        current_hash = evidence_hash(
            evidence,
            model=model,
            prompt_version=self.settings.gemini_prompt_version,
        )
        if not self.settings.gemini_ai_enabled:
            return GeminiAnalysisResult(
                candidate_id=candidate.candidate_id,
                evidence_hash=current_hash,
                status="skipped",
                error="Gemini AI disabled",
            )
        if not (self.settings.gemini_api_key or "").strip():
            return GeminiAnalysisResult(
                candidate_id=candidate.candidate_id,
                evidence_hash=current_hash,
                status="skipped",
                error="Gemini API key missing",
            )
        if not _eligible_for_ai(candidate):
            return GeminiAnalysisResult(
                candidate_id=candidate.candidate_id,
                evidence_hash=current_hash,
                status="skipped",
                error="Candidate not eligible for AI triage",
            )
        if self.settings.gemini_cache_enabled and not run_config.refresh_cache:
            cached = self.cache.get(current_hash)
            if cached is not None:
                self.cache_hits += 1
                return GeminiAnalysisResult(
                    candidate_id=candidate.candidate_id,
                    evidence_hash=current_hash,
                    status="valid",
                    analysis=GeminiSecurityAnalysis.model_validate(cached.response_json),
                    cache_hit=True,
                    input_tokens=cached.input_token_count,
                    output_tokens=cached.output_token_count,
                    analyzed_at=cached.analyzed_at,
                )
        client = self.client or GoogleGenAIClient(str(self.settings.gemini_api_key))
        payload = canonical_json(evidence)
        try:
            analysis, input_tokens, output_tokens = client.analyze(
                model=model,
                system_prompt=GEMINI_SECURITY_SYSTEM_PROMPT,
                user_payload=payload,
                max_output_tokens=self.settings.gemini_max_output_tokens,
            )
        except Exception as exc:  # noqa: BLE001
            return GeminiAnalysisResult(
                candidate_id=candidate.candidate_id,
                evidence_hash=current_hash,
                status="invalid",
                error=_safe_error(exc),
            )
        validation_error = validate_analysis_against_evidence(analysis, evidence)
        if validation_error:
            return GeminiAnalysisResult(
                candidate_id=candidate.candidate_id,
                evidence_hash=current_hash,
                status="invalid",
                error=validation_error,
            )
        self.calls += 1
        self.input_tokens += input_tokens
        self.output_tokens += output_tokens
        if self.settings.gemini_cache_enabled:
            self.cache.put(
                evidence_hash=current_hash,
                candidate_id=candidate.candidate_id,
                model=model,
                prompt_version=self.settings.gemini_prompt_version,
                schema_version=evidence.schema_version,
                analysis=analysis,
                input_token_count=input_tokens,
                output_token_count=output_tokens,
                status="valid",
            )
        return GeminiAnalysisResult(
            candidate_id=candidate.candidate_id,
            evidence_hash=current_hash,
            status="valid",
            analysis=analysis,
            input_tokens=input_tokens,
            output_tokens=output_tokens,
            analyzed_at=datetime.now(UTC).isoformat(),
        )

    def _model(self, config: GeminiRunConfig) -> str:
        return config.model or self.settings.gemini_triage_model


def validate_analysis_against_evidence(
    analysis: GeminiSecurityAnalysis,
    evidence: GeminiEvidenceBundle,
) -> str | None:
    known_ids = evidence.evidence_ids()
    for evidence_id in analysis.evidence_ids:
        if evidence_id not in known_ids:
            return f"unknown evidence_id: {evidence_id}"
    known_urls = set(evidence.public_urls)
    generated_text = " ".join(
        item
        for item in (
            analysis.root_cause,
            analysis.previous_behavior,
            analysis.added_protection,
            analysis.potential_impact,
            analysis.concise_explanation,
            *analysis.contradictions,
            *analysis.missing_information,
        )
        if item
    )
    invented = urls_in_text(generated_text) - known_urls
    if invented:
        return f"invented URL: {sorted(invented)[0]}"
    if (
        analysis.verdict == "confirmed_public_vulnerability"
        and analysis.public_information_level in {"none", "impact_only"}
    ):
        return "confirmed verdict requires explicit public technical evidence"
    return None


def _eligible_for_ai(candidate: RecentSecurityFixCandidate) -> bool:
    text = (
        f"{candidate.changelog_excerpt} {candidate.patch_summary} "
        f"{' '.join(candidate.changed_files)}"
    ).lower()
    if not candidate.old_version:
        return False
    if any(term in text for term in ("shader", "texture", "translation", "documentation")):
        return False
    return bool(
        candidate.changelog_excerpt
        or candidate.patch_summary
        or candidate.pull_request_url
        or candidate.issue_url
        or candidate.commit_url
        or candidate.changed_files
    )


def _prioritize_candidates(
    candidates: list[RecentSecurityFixCandidate],
) -> list[RecentSecurityFixCandidate]:
    return sorted(
        candidates,
        key=lambda item: (
            bool(item.patch_summary and item.patch_summary != "No linked diff available"),
            bool(item.old_version and item.fixed_version),
            len(item.affected_modpacks),
            bool(item.pull_request_url or item.issue_url),
            item.confidence,
        ),
        reverse=True,
    )


def _apply_analysis(
    candidate: RecentSecurityFixCandidate,
    result: GeminiAnalysisResult,
    model: str,
    config: GeminiRunConfig,
) -> RecentSecurityFixCandidate:
    analysis = result.analysis
    if analysis is None:
        return candidate
    return candidate.model_copy(
        update={
            "ai_provider": "gemini",
            "ai_model": model,
            "ai_review_model": config.review_model,
            "ai_verdict": analysis.verdict,
            "ai_confidence": analysis.confidence,
            "ai_category": analysis.category,
            "ai_root_cause": analysis.root_cause,
            "ai_previous_behavior": analysis.previous_behavior,
            "ai_added_protection": analysis.added_protection,
            "ai_potential_impact": analysis.potential_impact,
            "ai_public_information_level": analysis.public_information_level,
            "ai_requires_manual_review": analysis.requires_manual_review,
            "ai_concise_explanation": analysis.concise_explanation,
            "ai_evidence_hash": result.evidence_hash,
            "ai_analyzed_at": result.analyzed_at,
            "ai_cache_hit": result.cache_hit,
            "ai_missing_information": analysis.missing_information,
            "ai_contradictions": analysis.contradictions,
        }
    )


def _copy_ai_fields(
    candidate: RecentSecurityFixCandidate,
    source: RecentSecurityFixCandidate,
) -> RecentSecurityFixCandidate:
    fields = {
        key: getattr(source, key)
        for key in RecentSecurityFixCandidate.model_fields
        if key.startswith("ai_")
    }
    return candidate.model_copy(update=fields)


def _candidate_dedupe_key(
    candidate: RecentSecurityFixCandidate,
    bundle: GeminiEvidenceBundle,
) -> str:
    return "|".join(
        [
            candidate.repository or "",
            candidate.old_version,
            candidate.fixed_version,
            canonical_json(bundle.model_copy(update={"candidate_id": ""})),
        ]
    )


def _safe_error(exc: Exception) -> str:
    text = str(exc)
    if len(text) > 500:
        text = text[:500]
    return text.replace("\n", " ")
