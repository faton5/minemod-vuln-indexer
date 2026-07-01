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
