from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator

SCHEMA_VERSION = "gemini-security-analysis-v1"

GeminiVerdict = Literal[
    "unrelated",
    "normal_bugfix",
    "interesting_security_fix",
    "probable_exploitable_bug",
    "confirmed_public_vulnerability",
    "insufficient_evidence",
]

GeminiCategory = Literal[
    "duplication",
    "client_server_trust",
    "packet_validation",
    "nbt_validation",
    "authorization_bypass",
    "ownership_bypass",
    "replay_or_race",
    "denial_of_service",
    "unsafe_deserialization",
    "other",
    "unknown",
]

PublicInformationLevel = Literal[
    "none",
    "impact_only",
    "technical_description",
    "public_reproduction_steps",
    "public_poc",
]


class GeminiSecurityAnalysis(BaseModel):
    model_config = ConfigDict(extra="forbid")

    verdict: GeminiVerdict
    confidence: int
    category: GeminiCategory
    root_cause: str | None = None
    previous_behavior: str | None = None
    added_protection: str | None = None
    potential_impact: str | None = None
    attacker_prerequisites: list[str] = Field(default_factory=list)
    affected_version_confidence: int
    fixed_version_confidence: int
    public_information_level: PublicInformationLevel
    evidence_ids: list[str] = Field(default_factory=list)
    contradictions: list[str] = Field(default_factory=list)
    missing_information: list[str] = Field(default_factory=list)
    requires_manual_review: bool
    concise_explanation: str

    @field_validator("confidence", "affected_version_confidence", "fixed_version_confidence")
    @classmethod
    def _confidence_range(cls, value: int) -> int:
        if value < 0 or value > 100:
            raise ValueError("confidence must be between 0 and 100")
        return value


class GeminiEvidenceItem(BaseModel):
    evidence_id: str
    kind: str
    text: str | None = None
    url: str | None = None


class GeminiAffectedModpack(BaseModel):
    modpack: str
    modpack_release: str
    installed_version: str
    fixed_version: str
    same_minecraft_loader: bool
    latest_pack_release: bool
    days_since_fix: int | None = None
    download_count: int = 0


class GeminiEvidenceBundle(BaseModel):
    schema_version: str = SCHEMA_VERSION
    candidate_id: str
    mod_name: str
    provider: str
    provider_project_id: str
    repository: str | None = None
    old_version: str
    fixed_version: str
    minecraft_version: str | None = None
    loader: str | None = None
    release_date: str | None = None
    changed_files: list[str] = Field(default_factory=list)
    affected_modpack_count: int = 0
    affected_modpacks: list[GeminiAffectedModpack] = Field(default_factory=list)
    evidence: list[GeminiEvidenceItem] = Field(default_factory=list)
    public_urls: list[str] = Field(default_factory=list)
    truncated: bool = False

    def evidence_ids(self) -> set[str]:
        return {item.evidence_id for item in self.evidence}
