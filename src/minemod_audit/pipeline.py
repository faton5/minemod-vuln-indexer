from pathlib import Path

from minemod_audit.advisories import (
    GitHubClient,
    NvdClient,
    deduplicate_models,
    normalize_advisory,
)
from minemod_audit.config import Settings
from minemod_audit.curseforge import CurseForgeClient
from minemod_audit.database import DataStore
from minemod_audit.io import load_yaml_mapping
from minemod_audit.models import (
    Finding,
    Modpack,
    ModpackComponent,
    ModpackRelease,
    ModProject,
    RepositoryResolution,
    SourceType,
    Vulnerability,
)
from minemod_audit.reports import write_reports
from minemod_audit.repository import RepositoryCandidate, resolve_repository
from minemod_audit.versioning import VersionDecision, is_version_affected


class Pipeline:
    def __init__(
        self,
        settings: Settings,
        *,
        offline: bool = False,
        refresh: bool = False,
    ) -> None:
        self.settings = settings
        self.offline = offline
        self.refresh = refresh
        self.store = DataStore(settings.database)

    def collect_mods(self, *, limit: int) -> list[ModProject]:
        if not self.settings.curseforge_api_key:
            raise RuntimeError("CURSEFORGE_API_KEY is required for collect-mods")
        client = CurseForgeClient(
            api_key=self.settings.curseforge_api_key,
            cache_directory=self.settings.cache_directory,
            timeout_seconds=self.settings.timeout_seconds,
            offline=self.offline,
            refresh=self.refresh,
        )
        try:
            mods = client.collect_mods(limit=limit)
        finally:
            client.close()
        self.store.replace_models("mods", mods, key=lambda item: str(item.project_id))
        return mods

    def resolve_repositories(
        self,
        *,
        overrides_path: Path = Path("repo_overrides.yaml"),
    ) -> list[RepositoryResolution]:
        mods = self.store.load_models("mods", ModProject)
        overrides = load_yaml_mapping(overrides_path)
        github = GitHubClient(
            token=self.settings.github_token,
            cache_directory=self.settings.cache_directory,
            timeout_seconds=self.settings.timeout_seconds,
            offline=self.offline,
            refresh=self.refresh,
        )
        resolutions: list[RepositoryResolution] = []
        try:
            for mod in mods:
                candidates: list[RepositoryCandidate] = []
                if not mod.source_url and not mod.issues_url and not self.offline:
                    for raw in github.search_repositories(mod.name, mod.slug, mod.authors):
                        candidates.append(
                            RepositoryCandidate(
                                repository=str(raw.get("full_name")),
                                score=_score_repository_candidate(mod, raw),
                                source="github_search",
                            )
                        )
                resolutions.append(
                    resolve_repository(mod, overrides=overrides, candidates=candidates)
                )
        finally:
            github.close()
        self.store.replace_models(
            "repositories",
            resolutions,
            key=lambda item: str(item.mod_project_id),
        )
        return resolutions

    def collect_advisories(self) -> list[Vulnerability]:
        repositories = self.store.load_models("repositories", RepositoryResolution)
        github = GitHubClient(
            token=self.settings.github_token,
            cache_directory=self.settings.cache_directory,
            timeout_seconds=self.settings.timeout_seconds,
            offline=self.offline,
            refresh=self.refresh,
        )
        nvd = NvdClient(
            api_key=self.settings.nvd_api_key,
            cache_directory=self.settings.cache_directory,
            timeout_seconds=self.settings.timeout_seconds,
            offline=self.offline,
            refresh=self.refresh,
        )
        vulnerabilities: list[Vulnerability] = []
        try:
            for repository in repositories:
                if not repository.repository:
                    continue
                for raw in github.collect_global_advisories(repository.repository):
                    vulnerabilities.append(
                        normalize_advisory(raw, repository=repository, source_type=SourceType.GHSA)
                    )
                for raw in github.collect_repository_advisories(repository.repository):
                    vulnerabilities.append(
                        normalize_advisory(
                            raw,
                            repository=repository,
                            source_type=SourceType.REPOSITORY_ADVISORY,
                        )
                    )
                if not self.offline:
                    for raw in nvd.search_keyword(repository.mod_name):
                        cve = raw.get("cve", {}) if isinstance(raw, dict) else {}
                        vulnerabilities.append(
                            normalize_advisory(
                                cve, repository=repository, source_type=SourceType.NVD
                            )
                        )
                    for raw in github.collect_repository_signals(repository.repository):
                        vulnerabilities.append(
                            normalize_advisory(
                                raw,
                                repository=repository,
                                source_type=SourceType.ISSUE,
                            )
                        )
        finally:
            github.close()
            nvd.close()
        vulnerabilities = deduplicate_models(vulnerabilities)
        self.store.replace_models(
            "vulnerabilities",
            vulnerabilities,
            key=lambda item: item.internal_id,
        )
        return vulnerabilities

    def index_modpacks(
        self,
        *,
        limit: int,
        releases_per_pack: int,
        minecraft_version: str | None = None,
        loader: str | None = None,
    ) -> tuple[list[Modpack], list[ModpackRelease], list[ModpackComponent]]:
        if not self.settings.curseforge_api_key:
            raise RuntimeError("CURSEFORGE_API_KEY is required for index-modpacks")
        client = CurseForgeClient(
            api_key=self.settings.curseforge_api_key,
            cache_directory=self.settings.cache_directory,
            timeout_seconds=self.settings.timeout_seconds,
            offline=self.offline,
            refresh=self.refresh,
        )
        releases: list[ModpackRelease] = []
        components: list[ModpackComponent] = []
        try:
            modpacks = client.collect_modpacks(limit=limit, minecraft_version=minecraft_version)
            for modpack in modpacks:
                files = client.get_files(modpack.project_id, page_size=releases_per_pack)
                for file_payload in files:
                    release, release_components = client.index_modpack_release(
                        modpack=modpack,
                        file_payload=file_payload,
                    )
                    if loader and release.loader and release.loader.lower() != loader.lower():
                        continue
                    releases.append(release)
                    components.extend(release_components)
        finally:
            client.close()
        self.store.replace_models("modpacks", modpacks, key=lambda item: str(item.project_id))
        self.store.replace_models("modpack_releases", releases, key=lambda item: str(item.file_id))
        self.store.replace_models(
            "modpack_components",
            components,
            key=lambda item: f"{item.modpack_file_id}:{item.mod_project_id}:{item.mod_file_id}",
        )
        return modpacks, releases, components

    def correlate(self) -> list[Finding]:
        vulnerabilities = self.store.load_models("vulnerabilities", Vulnerability)
        components = self.store.load_models("modpack_components", ModpackComponent)
        releases = {
            item.file_id: item
            for item in self.store.load_models("modpack_releases", ModpackRelease)
        }
        modpacks = {item.project_id: item for item in self.store.load_models("modpacks", Modpack)}
        mods = {item.project_id: item for item in self.store.load_models("mods", ModProject)}

        findings: list[Finding] = []
        for component in components:
            component_version = component.mod_version or component.filename or ""
            for vulnerability in vulnerabilities:
                if vulnerability.mod_project_id != component.mod_project_id:
                    continue
                affected_rule = (
                    vulnerability.affected_versions[0] if vulnerability.affected_versions else None
                )
                fixed_rule = (
                    vulnerability.fixed_versions[0] if vulnerability.fixed_versions else None
                )
                decision = is_version_affected(
                    component_version,
                    affected=affected_rule,
                    fixed=fixed_rule,
                )
                if decision == VersionDecision.NOT_AFFECTED:
                    continue
                release = releases.get(component.modpack_file_id)
                modpack = modpacks.get(release.modpack_project_id) if release else None
                mod = mods.get(component.mod_project_id)
                findings.append(
                    Finding(
                        mod_name=(
                            component.mod_name
                            or vulnerability.mod_name
                            or (mod.name if mod else "unknown")
                        ),
                        mod_version=component_version or "unknown",
                        modpack_name=modpack.name if modpack else "unknown",
                        modpack_release=(
                            release.display_name if release else str(component.modpack_file_id)
                        ),
                        minecraft_version=release.minecraft_version if release else None,
                        loader=release.loader if release else None,
                        affected_range=affected_rule,
                        fixed_versions=vulnerability.fixed_versions,
                        impact_category=vulnerability.impact_category,
                        confidence=vulnerability.confidence,
                        status=vulnerability.status,
                        source_urls=[str(vulnerability.source_url)],
                        requires_manual_review=decision == VersionDecision.MANUAL_REVIEW
                        or vulnerability.requires_manual_review,
                        manual_review_reason="version comparison is not reliable"
                        if decision == VersionDecision.MANUAL_REVIEW
                        else None,
                    )
                )
        self.store.replace_models(
            "findings",
            findings,
            key=lambda item: (
                f"{item.modpack_name}:{item.modpack_release}:{item.mod_name}:{item.mod_version}"
            ),
        )
        return findings

    def report(self) -> None:
        write_reports(
            self.settings.output_directory,
            mods=self.store.load_models("mods", ModProject),
            repositories=self.store.load_models("repositories", RepositoryResolution),
            vulnerabilities=self.store.load_models("vulnerabilities", Vulnerability),
            components=self.store.load_models("modpack_components", ModpackComponent),
            findings=self.store.load_models("findings", Finding),
        )


def _score_repository_candidate(mod: ModProject, raw: dict[str, object]) -> int:
    score = 0
    full_name = str(raw.get("full_name") or "").lower()
    name = str(raw.get("name") or "").lower()
    owner = full_name.split("/", maxsplit=1)[0] if "/" in full_name else ""
    if name in {mod.slug.lower(), mod.name.lower().replace(" ", "-")}:
        score += 50
    if any(author.lower() == owner for author in mod.authors):
        score += 30
    if str(raw.get("archived")).lower() == "false":
        score += 5
    return score
