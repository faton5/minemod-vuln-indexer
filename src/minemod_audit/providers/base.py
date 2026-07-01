from typing import Any, Literal, Protocol

from pydantic import BaseModel, Field

ProviderName = Literal["modrinth", "curseforge"]


class ProviderAuthor(BaseModel):
    name: str
    url: str | None = None


class ProviderLink(BaseModel):
    label: str
    url: str


class ProviderFile(BaseModel):
    filename: str
    url: str | None = None
    hashes: dict[str, str] = Field(default_factory=dict)
    size: int | None = None
    primary: bool = False


class ProviderDependency(BaseModel):
    provider: ProviderName
    provider_project_id: str | None = None
    provider_version_id: str | None = None
    dependency_type: str
    raw_metadata: dict[str, Any] = Field(default_factory=dict)


class ProviderVersion(BaseModel):
    provider: ProviderName
    provider_project_id: str
    provider_version_id: str
    version_number: str
    publication_date: str | None = None
    loaders: list[str] = Field(default_factory=list)
    game_versions: list[str] = Field(default_factory=list)
    dependencies: list[ProviderDependency] = Field(default_factory=list)
    files: list[ProviderFile] = Field(default_factory=list)
    raw_metadata: dict[str, Any] = Field(default_factory=dict)


class ProviderProject(BaseModel):
    provider: ProviderName
    provider_project_id: str
    slug: str
    title: str
    project_type: str
    downloads: int = 0
    description: str | None = None
    source_url: str | None = None
    issues_url: str | None = None
    website_url: str | None = None
    client_side: str | None = None
    server_side: str | None = None
    loaders: list[str] = Field(default_factory=list)
    game_versions: list[str] = Field(default_factory=list)
    authors: list[ProviderAuthor] = Field(default_factory=list)
    links: list[ProviderLink] = Field(default_factory=list)
    raw_metadata: dict[str, Any] = Field(default_factory=dict)


class ProviderStatus(BaseModel):
    name: str
    status: Literal["enabled", "disabled", "warning"]
    priority: int | None = None
    reason: str


class ProjectProvider(Protocol):
    name: ProviderName

    def list_popular_mods(self, limit: int, offset: int = 0) -> list[ProviderProject]: ...

    def list_popular_modpacks(self, limit: int, offset: int = 0) -> list[ProviderProject]: ...

    def get_project(self, project_id_or_slug: str) -> ProviderProject: ...

    def get_projects(self, project_ids: list[str]) -> dict[str, ProviderProject]: ...

    def get_project_versions(self, project_id_or_slug: str) -> list[ProviderVersion]: ...

    def get_version(self, version_id: str) -> ProviderVersion: ...

    def get_versions(self, version_ids: list[str]) -> dict[str, ProviderVersion]: ...

    def get_project_dependencies(self, project_id_or_slug: str) -> list[ProviderDependency]: ...

    def health_check(self) -> ProviderStatus: ...

    def close(self) -> None: ...
