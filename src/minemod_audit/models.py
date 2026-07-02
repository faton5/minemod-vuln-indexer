from enum import StrEnum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, HttpUrl


class SourceType(StrEnum):
    GHSA = "ghsa"
    REPOSITORY_ADVISORY = "repository_advisory"
    OSV = "osv"
    NVD = "nvd"
    RELEASE = "release"
    ISSUE = "issue"
    PULL_REQUEST = "pull_request"
    COMMIT = "commit"
    CHANGELOG = "changelog"
    MANUAL_RULE = "manual_rule"


class ImpactCategory(StrEnum):
    ITEM_CREATION = "item_creation"
    ITEM_DUPLICATION = "item_duplication"
    INVENTORY_MODIFICATION = "inventory_modification"
    TELEPORTATION = "teleportation"
    PERMISSION_BYPASS = "permission_bypass"
    AUTHENTICATION_BYPASS = "authentication_bypass"
    DATA_MODIFICATION = "data_modification"
    SERVER_CRASH = "server_crash"
    DENIAL_OF_SERVICE = "denial_of_service"
    REMOTE_CODE_EXECUTION = "remote_code_execution"
    CLIENT_COMPROMISE = "client_compromise"
    INFORMATION_DISCLOSURE = "information_disclosure"
    OTHER = "other"


class AttackDirection(StrEnum):
    CLIENT_TO_SERVER = "client_to_server"
    SERVER_TO_CLIENT = "server_to_client"
    LOCAL = "local"
    UNKNOWN = "unknown"


class VulnerabilityStatus(StrEnum):
    CONFIRMED = "confirmed"
    LIKELY = "likely"
    CANDIDATE = "candidate"
    FIXED = "fixed"
    WITHDRAWN = "withdrawn"
    UNCLEAR = "unclear"


class ModProject(BaseModel):
    model_config = ConfigDict(extra="allow")

    project_id: int | str
    provider: str | None = None
    provider_project_id: str | None = None
    name: str
    slug: str
    authors: list[str] = Field(default_factory=list)
    download_count: int = 0
    date_modified: str | None = None
    class_id: int | None = None
    primary_category_id: int | None = None
    source_url: str | None = None
    issues_url: str | None = None
    website_url: str | None = None
    main_file_id: int | None = None
    categories: list[str] = Field(default_factory=list)
    latest_versions: list[str] = Field(default_factory=list)
    raw: dict[str, Any] = Field(default_factory=dict)


class RepositoryResolution(BaseModel):
    mod_project_id: int | str
    mod_name: str
    repository: str | None
    confidence: int
    status: str
    source: str
    evidence: str


class Vulnerability(BaseModel):
    internal_id: str
    mod_project_id: int | str
    mod_name: str
    repository: str | None = None
    title: str
    description: str = ""
    source_type: SourceType
    source_url: HttpUrl | str
    ghsa_id: str | None = None
    cve_id: str | None = None
    osv_id: str | None = None
    published_at: str | None = None
    updated_at: str | None = None
    severity: str | None = None
    cvss: float | None = None
    cwes: list[str] = Field(default_factory=list)
    impact_category: str = ImpactCategory.OTHER.value
    attack_direction: str = AttackDirection.UNKNOWN.value
    prerequisites: str | None = None
    minecraft_versions: list[str] = Field(default_factory=list)
    loaders: list[str] = Field(default_factory=list)
    affected_versions: list[str] = Field(default_factory=list)
    fixed_versions: list[str] = Field(default_factory=list)
    status: str = VulnerabilityStatus.CANDIDATE.value
    confidence: int = 0
    evidence: list[str] = Field(default_factory=list)
    requires_manual_review: bool = True


class Modpack(BaseModel):
    project_id: int | str
    provider: str | None = None
    provider_project_id: str | None = None
    name: str
    slug: str
    download_count: int = 0


class ModpackRelease(BaseModel):
    file_id: int | str
    modpack_project_id: int | str
    display_name: str
    release_date: str | None = None
    minecraft_version: str | None = None
    loader: str | None = None
    download_url: str | None = None
    sha256: str | None = None
    unresolved_reason: str | None = None


class ModpackComponent(BaseModel):
    modpack_file_id: int | str
    mod_project_id: int | str
    mod_file_id: int | str
    provider: str | None = None
    provider_project_id: str | None = None
    provider_version_id: str | None = None
    mod_name: str | None = None
    mod_version: str | None = None
    filename: str | None = None
    hashes: dict[str, str] = Field(default_factory=dict)
    loaders: list[str] = Field(default_factory=list)
    minecraft_versions: list[str] = Field(default_factory=list)
    source_url: str | None = None
    resolution_status: str = "unresolved"
    requires_manual_review: bool = True
    required: bool = True


class PrioritizedMod(BaseModel):
    project_id: int | str
    provider: str
    provider_project_id: str
    name: str
    slug: str
    download_count: int = 0
    dependency_count: int = 0
    modpack_count: int = 0
    score: int = 0
    source_url: str | None = None
    issues_url: str | None = None
    repository: str | None = None
    requires_manual_review: bool = False


class SecurityEvidenceBundle(BaseModel):
    mod_project_id: int | str
    mod_name: str
    repository: str
    issue_url: str | None = None
    pull_request_url: str | None = None
    pull_request_merged_at: str | None = None
    commit_sha: str | None = None
    commit_url: str | None = None
    release_url: str | None = None
    release_version: str | None = None
    published_at: str | None = None
    updated_at: str | None = None
    matched_terms: list[str] = Field(default_factory=list)
    changed_files: list[str] = Field(default_factory=list)
    patch_summary: str | None = None
    author_is_maintainer: bool = False
    maintainer_confirmed_security_impact: bool = False
    maintainer_confirmation: bool = False
    affected_versions: list[str] = Field(default_factory=list)
    fixed_versions: list[str] = Field(default_factory=list)
    impact_category: str = ImpactCategory.OTHER.value
    attack_direction: str = AttackDirection.UNKNOWN.value
    prerequisites: str | None = None
    confidence: int = 0
    status: str = "weak_signal"
    reasons: list[str] = Field(default_factory=list)
    requires_manual_review: bool = True


class CanonicalMod(BaseModel):
    canonical_id: str
    github_repository: str | None = None
    curseforge_project_ids: list[str] = Field(default_factory=list)
    modrinth_project_ids: list[str] = Field(default_factory=list)
    aliases: list[str] = Field(default_factory=list)
    loaders: list[str] = Field(default_factory=list)
    minecraft_branches: list[str] = Field(default_factory=list)


class ReleaseLagLibrary(BaseModel):
    canonical_mod_id: str
    mod_name: str
    modpack_release_count: int
    modpack_count: int
    github_repository: str | None = None


class ReleaseDiffCandidate(BaseModel):
    canonical_mod_id: str
    old_version: str
    new_version: str
    old_tag: str | None = None
    new_tag: str | None = None
    changed_files: list[str] = Field(default_factory=list)
    relevant_patch_sections: list[str] = Field(default_factory=list)
    category: str
    explanation: str
    confidence: int
    fixed_commit: str | None = None
    published_at: str | None = None
    minecraft_branch: str | None = None
    loader: str | None = None


class ReleaseLagFinding(BaseModel):
    canonical_mod_id: str
    mod_name: str
    modpack_name: str
    modpack_release: str
    old_version: str
    new_version: str
    status: str
    days_since_fix: int | None = None
    latest_pack_release: bool = False
    minecraft_branch: str | None = None
    loader: str | None = None
    confidence: int
    evidence_urls: list[str] = Field(default_factory=list)
    requires_manual_review: bool = True


class AffectedModpack(BaseModel):
    modpack: str
    modpack_release: str
    installed_version: str
    fixed_version: str
    same_minecraft_loader: bool
    latest_pack_release: bool
    days_since_fix: int | None = None
    download_count: int = 0


class RecentSecurityFixCandidate(BaseModel):
    candidate_id: str
    mod_name: str
    repository: str | None = None
    provider: str
    provider_project_id: str
    old_file_id: str | None = None
    new_file_id: str | None = None
    old_version: str
    fixed_version: str
    minecraft_version: str | None = None
    loader: str | None = None
    release_date: str | None = None
    changelog_excerpt: str
    issue_url: str | None = None
    pull_request_url: str | None = None
    commit_url: str | None = None
    changed_files: list[str] = Field(default_factory=list)
    patch_summary: str
    potential_impact: str
    prerequisites: str | None = None
    public_exploit_information: str = "none"
    confidence: int
    category: str
    affected_modpacks: list[AffectedModpack] = Field(default_factory=list)
    requires_manual_review: bool = True
    ai_provider: str | None = None
    ai_model: str | None = None
    ai_review_model: str | None = None
    ai_verdict: str | None = None
    ai_confidence: int | None = None
    ai_category: str | None = None
    ai_root_cause: str | None = None
    ai_previous_behavior: str | None = None
    ai_added_protection: str | None = None
    ai_potential_impact: str | None = None
    ai_public_information_level: str | None = None
    ai_requires_manual_review: bool = False
    ai_concise_explanation: str | None = None
    ai_evidence_hash: str | None = None
    ai_analyzed_at: str | None = None
    ai_cache_hit: bool = False
    ai_status: str | None = None
    ai_error: str | None = None
    ai_missing_information: list[str] = Field(default_factory=list)
    ai_contradictions: list[str] = Field(default_factory=list)


class CrawlerEvent(BaseModel):
    event_id: str
    run_id: str
    stage: str
    level: str = "info"
    message: str
    created_at: str
    candidate_id: str | None = None
    mod_name: str | None = None
    data: dict[str, Any] = Field(default_factory=dict)


class Finding(BaseModel):
    mod_name: str
    mod_version: str
    modpack_name: str
    modpack_release: str
    minecraft_version: str | None = None
    loader: str | None = None
    affected_range: str | None = None
    fixed_versions: list[str] = Field(default_factory=list)
    impact_category: str
    confidence: int
    status: str
    source_urls: list[str] = Field(default_factory=list)
    requires_manual_review: bool = False
    manual_review_reason: str | None = None
