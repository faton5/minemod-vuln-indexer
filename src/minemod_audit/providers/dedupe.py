from pydantic import BaseModel

from minemod_audit.providers.base import ProviderProject
from minemod_audit.repository import extract_github_repository


class DeduplicatedProviderProject(BaseModel):
    primary: ProviderProject
    sources: list[ProviderProject]
    conflicts: dict[str, list[str]]


def deduplicate_provider_projects(
    projects: list[ProviderProject],
) -> list[DeduplicatedProviderProject]:
    buckets: dict[str, list[ProviderProject]] = {}
    for project in projects:
        key = _dedupe_key(project)
        buckets.setdefault(key, []).append(project)
    return [_merge_bucket(bucket) for bucket in buckets.values()]


def _dedupe_key(project: ProviderProject) -> str:
    repository = extract_github_repository(project.source_url)
    if repository:
        return f"github:{repository.lower()}"
    return f"{project.provider}:{project.provider_project_id}"


def _merge_bucket(projects: list[ProviderProject]) -> DeduplicatedProviderProject:
    primary = next((project for project in projects if project.provider == "modrinth"), projects[0])
    conflicts: dict[str, list[str]] = {}
    for field in ("source_url", "issues_url", "website_url"):
        values = sorted(
            {str(getattr(project, field)) for project in projects if getattr(project, field)}
        )
        if len(values) > 1:
            conflicts[field] = values
    return DeduplicatedProviderProject(primary=primary, sources=projects, conflicts=conflicts)
