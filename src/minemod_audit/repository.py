from dataclasses import dataclass
from urllib.parse import urlparse

from minemod_audit.models import ModProject, RepositoryResolution


@dataclass(frozen=True)
class RepositoryCandidate:
    repository: str
    score: int
    source: str


def extract_github_repository(url: str | None) -> str | None:
    if not url:
        return None
    parsed = urlparse(url)
    if parsed.netloc.lower() not in {"github.com", "www.github.com"}:
        return None
    parts = [part for part in parsed.path.strip("/").split("/") if part]
    if len(parts) < 2:
        return None
    owner, repo = parts[0], parts[1]
    if repo in {"issues", "pulls"}:
        return None
    return f"{owner}/{repo.removesuffix('.git')}"


def resolve_repository(
    mod: ModProject,
    *,
    overrides: dict[int, dict[str, object]],
    candidates: list[RepositoryCandidate],
) -> RepositoryResolution:
    override_key = int(str(mod.project_id)) if str(mod.project_id).isdigit() else None
    override = overrides.get(override_key) if override_key is not None else None
    if override is not None:
        repository = override.get("repository")
        confidence = int(str(override.get("confidence", 100)))
        return RepositoryResolution(
            mod_project_id=mod.project_id,
            mod_name=mod.name,
            repository=str(repository) if repository else None,
            confidence=confidence,
            status="resolved" if repository else "unresolved",
            source="repo_overrides.yaml",
            evidence="manual override",
        )

    source_repository = extract_github_repository(mod.source_url)
    if source_repository:
        return RepositoryResolution(
            mod_project_id=mod.project_id,
            mod_name=mod.name,
            repository=source_repository,
            confidence=100,
            status="resolved",
            source="curseforge_source_url",
            evidence=mod.source_url or "",
        )

    issues_repository = extract_github_repository(mod.issues_url)
    if issues_repository:
        return RepositoryResolution(
            mod_project_id=mod.project_id,
            mod_name=mod.name,
            repository=issues_repository,
            confidence=80,
            status="resolved",
            source="curseforge_issues_url",
            evidence=mod.issues_url or "",
        )

    strongest_score = max((candidate.score for candidate in candidates), default=0)
    strongest = [candidate for candidate in candidates if candidate.score == strongest_score]
    if len(strongest) == 1 and strongest_score >= 80:
        candidate = strongest[0]
        return RepositoryResolution(
            mod_project_id=mod.project_id,
            mod_name=mod.name,
            repository=candidate.repository,
            confidence=50,
            status="resolved",
            source=candidate.source,
            evidence="single strong GitHub search match",
        )

    return RepositoryResolution(
        mod_project_id=mod.project_id,
        mod_name=mod.name,
        repository=None,
        confidence=0,
        status="ambiguous" if candidates else "unresolved",
        source="github_search",
        evidence="no unambiguous official repository candidate",
    )
