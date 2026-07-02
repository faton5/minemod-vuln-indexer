from __future__ import annotations

from datetime import UTC, datetime

from pydantic import BaseModel, Field

from minemod_audit.ai.schemas import GeminiSecurityAnalysis
from minemod_audit.database import DataStore

CACHE_KIND = "gemini_analysis_cache"


class GeminiAnalysisCacheEntry(BaseModel):
    evidence_hash: str
    candidate_id: str
    model: str
    prompt_version: str
    schema_version: str
    response_json: dict[str, object] = Field(default_factory=dict)
    input_token_count: int = 0
    output_token_count: int = 0
    analyzed_at: str
    status: str


class GeminiAnalysisCache:
    def __init__(self, store: DataStore) -> None:
        self.store = store

    def get(self, evidence_hash: str) -> GeminiAnalysisCacheEntry | None:
        for entry in self.store.load_models(CACHE_KIND, GeminiAnalysisCacheEntry):
            if entry.evidence_hash == evidence_hash and entry.status == "valid":
                return entry
        return None

    def put(
        self,
        *,
        evidence_hash: str,
        candidate_id: str,
        model: str,
        prompt_version: str,
        schema_version: str,
        analysis: GeminiSecurityAnalysis,
        input_token_count: int,
        output_token_count: int,
        status: str,
    ) -> GeminiAnalysisCacheEntry:
        entry = GeminiAnalysisCacheEntry(
            evidence_hash=evidence_hash,
            candidate_id=candidate_id,
            model=model,
            prompt_version=prompt_version,
            schema_version=schema_version,
            response_json=analysis.model_dump(mode="json"),
            input_token_count=input_token_count,
            output_token_count=output_token_count,
            analyzed_at=datetime.now(UTC).isoformat(),
            status=status,
        )
        self.store.append_models(CACHE_KIND, [entry], key=lambda item: item.evidence_hash)
        return entry
