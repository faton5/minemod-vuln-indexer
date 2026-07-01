from pathlib import Path

import httpx

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
from minemod_audit.providers.base import (
    ProviderDependency,
    ProviderProject,
    ProviderStatus,
    ProviderVersion,
)
from minemod_audit.providers.dedupe import deduplicate_provider_projects
from minemod_audit.providers.registry import ProviderRegistry
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

    def provider_status(self) -> list[ProviderStatus]:
        return ProviderRegistry(
            self.settings,
            offline=self.offline,
            refresh=self.refresh,
        ).status()

    def collect_mods(self, *, limit: int, provider: str = "modrinth") -> list[ModProject]:
        provider_projects = self._collect_provider_projects(
            provider=provider,
            project_type="mod",
            limit=limit,
        )
        deduped_projects = deduplicate_provider_projects(provider_projects)
        mods = [self._mod_from_provider_project(group.primary) for group in deduped_projects]
        self.store.replace_models(
            "provider_projects",
            provider_projects,
            key=lambda item: f"{item.provider}:{item.provider_project_id}",
        )
        self.store.replace_models(
            "provider_project_groups",
            deduped_projects,
            key=lambda item: f"{item.primary.provider}:{item.primary.provider_project_id}",
        )
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
        return self.index_curseforge_modpacks(
            limit=limit,
            releases_per_pack=releases_per_pack,
            minecraft_version=minecraft_version,
            loader=loader,
        )

    def collect_modpacks(
        self,
        *,
        limit: int,
        provider: str = "modrinth",
    ) -> list[Modpack]:
        provider_projects = self._collect_provider_projects(
            provider=provider,
            project_type="modpack",
            limit=limit,
        )
        versions: list[ProviderVersion] = []
        for project in provider_projects:
            if project.provider != "modrinth":
                continue
            provider_client = ProviderRegistry(
                self.settings,
                offline=self.offline,
                refresh=self.refresh,
            ).build_provider(project.provider)
            try:
                versions.extend(provider_client.get_project_versions(project.provider_project_id))
            finally:
                provider_client.close()
        deduped_projects = deduplicate_provider_projects(provider_projects)
        modpacks = [
            self._modpack_from_provider_project(group.primary) for group in deduped_projects
        ]
        releases = [self._release_from_provider_version(version) for version in versions]
        components = [
            self._component_from_provider_dependency(version, dependency)
            for version in versions
            for dependency in version.dependencies
            if dependency.provider_project_id
        ]
        self.store.replace_models(
            "provider_projects",
            provider_projects,
            key=lambda item: f"{item.provider}:{item.provider_project_id}",
        )
        self.store.replace_models(
            "provider_project_groups",
            deduped_projects,
            key=lambda item: f"{item.primary.provider}:{item.primary.provider_project_id}",
        )
        self.store.replace_models(
            "provider_versions",
            versions,
            key=lambda item: f"{item.provider}:{item.provider_version_id}",
        )
        self.store.replace_models("modpacks", modpacks, key=lambda item: str(item.project_id))
        self.store.replace_models("modpack_releases", releases, key=lambda item: str(item.file_id))
        self.store.replace_models(
            "modpack_components",
            components,
            key=lambda item: f"{item.modpack_file_id}:{item.mod_project_id}:{item.mod_file_id}",
        )
        return modpacks

    def index_curseforge_modpacks(
        self,
        *,
        limit: int,
        releases_per_pack: int,
        minecraft_version: str | None = None,
        loader: str | None = None,
    ) -> tuple[list[Modpack], list[ModpackRelease], list[ModpackComponent]]:
        if not self.settings.curseforge_api_key:
            return [], [], []
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
                files = client.get_files(int(modpack.project_id), page_size=releases_per_pack)
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

    def _collect_provider_projects(
        self,
        *,
        provider: str,
        project_type: str,
        limit: int,
    ) -> list[ProviderProject]:
        registry = ProviderRegistry(
            self.settings,
            offline=self.offline,
            refresh=self.refresh,
        )
        provider_names = registry.enabled_provider_names(provider)
        projects: list[ProviderProject] = []
        for provider_name in provider_names:
            client = registry.build_provider(provider_name)
            try:
                if project_type == "mod":
                    projects.extend(client.list_popular_mods(limit=limit, offset=0))
                else:
                    projects.extend(client.list_popular_modpacks(limit=limit, offset=0))
            except httpx.HTTPStatusError as exc:
                if provider_name == "curseforge" and exc.response.status_code in {401, 403}:
                    continue
                raise
            finally:
                client.close()
        return projects[:limit] if provider != "all" else projects

    @staticmethod
    def _mod_from_provider_project(project: ProviderProject) -> ModProject:
        return ModProject(
            project_id=f"{project.provider}:{project.provider_project_id}",
            provider=project.provider,
            provider_project_id=project.provider_project_id,
            name=project.title,
            slug=project.slug,
            download_count=project.downloads,
            source_url=project.source_url,
            issues_url=project.issues_url,
            website_url=project.website_url,
            categories=project.loaders,
            latest_versions=project.game_versions,
            raw=project.raw_metadata,
        )

    @staticmethod
    def _modpack_from_provider_project(project: ProviderProject) -> Modpack:
        return Modpack(
            project_id=f"{project.provider}:{project.provider_project_id}",
            provider=project.provider,
            provider_project_id=project.provider_project_id,
            name=project.title,
            slug=project.slug,
            download_count=project.downloads,
        )

    @staticmethod
    def _release_from_provider_version(version: ProviderVersion) -> ModpackRelease:
        return ModpackRelease(
            file_id=f"{version.provider}:{version.provider_version_id}",
            modpack_project_id=f"{version.provider}:{version.provider_project_id}",
            display_name=version.version_number,
            release_date=version.publication_date,
            minecraft_version=version.game_versions[0] if version.game_versions else None,
            loader=version.loaders[0] if version.loaders else None,
        )

    @staticmethod
    def _component_from_provider_dependency(
        version: ProviderVersion,
        dependency: ProviderDependency,
    ) -> ModpackComponent:
        provider_project_id = dependency.provider_project_id
        provider_version_id = dependency.provider_version_id or provider_project_id
        return ModpackComponent(
            modpack_file_id=f"{version.provider}:{version.provider_version_id}",
            mod_project_id=f"{version.provider}:{provider_project_id}",
            mod_file_id=f"{version.provider}:{provider_version_id}",
            required=dependency.dependency_type == "required",
        )

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
