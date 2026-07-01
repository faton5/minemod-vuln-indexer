from collections import Counter
from datetime import datetime
from pathlib import Path

import httpx

from minemod_audit.advisories import GitHubClient, deduplicate_models, normalize_advisory
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
    PrioritizedMod,
    RepositoryResolution,
    SecurityEvidenceBundle,
    SourceType,
    Vulnerability,
)
from minemod_audit.providers.base import (
    ProviderDependency,
    ProviderFile,
    ProviderProject,
    ProviderStatus,
    ProviderVersion,
)
from minemod_audit.providers.dedupe import deduplicate_provider_projects
from minemod_audit.providers.registry import ProviderRegistry
from minemod_audit.reports import write_reports
from minemod_audit.repository import (
    RepositoryCandidate,
    extract_github_repository,
    resolve_repository,
)
from minemod_audit.security import classify_impact
from minemod_audit.security_discovery import (
    RECENT_FIX_TERMS,
    detect_matched_terms,
    infer_fixed_versions,
    patch_adds_server_validation,
    score_security_bundle,
    since_for_lookback,
    summarize_patch,
    visible_recent_fix_bundles,
)
from minemod_audit.versioning import VersionDecision, is_version_affected

TARGETED_SECURITY_TERMS: tuple[str, ...] = (
    "CVE",
    "GHSA",
    "vulnerability",
    "security",
    "exploit",
    "dupe",
    "duplication",
    "server crash",
    "permission bypass",
    "authorization",
    "deserialization",
)


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
        finally:
            github.close()
        vulnerabilities = deduplicate_models(vulnerabilities)
        self.store.replace_models(
            "vulnerabilities",
            vulnerabilities,
            key=lambda item: item.internal_id,
        )
        return vulnerabilities

    def prioritize_mods(self, *, top: int = 10, provider: str = "modrinth") -> list[PrioritizedMod]:
        components = self.store.load_models("modpack_components", ModpackComponent)
        component_counts = Counter(str(component.mod_project_id) for component in components)
        modpack_counts = {
            project_id: len(
                {
                    str(component.modpack_file_id)
                    for component in components
                    if str(component.mod_project_id) == project_id
                }
            )
            for project_id in component_counts
        }

        existing_mods = {
            str(mod.project_id): mod for mod in self.store.load_models("mods", ModProject)
        }
        ranked_project_ids = [
            project_id
            for project_id, _count in component_counts.most_common()
            if project_id.startswith(f"{provider}:")
        ]
        if not ranked_project_ids:
            ranked_project_ids = [
                str(mod.project_id)
                for mod in sorted(
                    existing_mods.values(),
                    key=lambda item: item.download_count,
                    reverse=True,
                )
                if str(mod.project_id).startswith(f"{provider}:")
            ]

        provider_client = ProviderRegistry(
            self.settings,
            offline=self.offline,
            refresh=self.refresh,
        ).build_provider(provider)
        prioritized: list[PrioritizedMod] = []
        fetched_mods: list[ModProject] = []
        try:
            for project_id in ranked_project_ids[:top]:
                mod = existing_mods.get(project_id)
                provider_project_id = project_id.split(":", maxsplit=1)[1]
                if mod is None or not (mod.source_url or mod.issues_url):
                    project = provider_client.get_project(provider_project_id)
                    mod = self._mod_from_provider_project(project)
                    fetched_mods.append(mod)
                dependency_count = component_counts.get(project_id, 0)
                modpack_count = modpack_counts.get(project_id, 0)
                repository = extract_github_repository(mod.source_url) or extract_github_repository(
                    mod.issues_url
                )
                prioritized.append(
                    PrioritizedMod(
                        project_id=mod.project_id,
                        provider=provider,
                        provider_project_id=provider_project_id,
                        name=mod.name,
                        slug=mod.slug,
                        download_count=mod.download_count,
                        dependency_count=dependency_count,
                        modpack_count=modpack_count,
                        score=(dependency_count * 1000) + mod.download_count,
                        source_url=mod.source_url,
                        issues_url=mod.issues_url,
                        repository=repository,
                        requires_manual_review=repository is None,
                    )
                )
        finally:
            provider_client.close()

        if fetched_mods:
            self.store.append_models("mods", fetched_mods, key=lambda item: str(item.project_id))
        prioritized.sort(key=lambda item: item.score, reverse=True)
        self.store.replace_models(
            "prioritized_mods",
            prioritized,
            key=lambda item: str(item.project_id),
        )
        return prioritized

    def mine_security_signals(
        self,
        *,
        top: int = 10,
        terms: tuple[str, ...] = TARGETED_SECURITY_TERMS,
        per_term: int = 5,
    ) -> list[Vulnerability]:
        del terms
        bundles = self.discover_recent_fixes(
            top=top,
            lookback_days=self.settings.security_lookback_days,
            per_term=per_term,
        )
        vulnerabilities = [
            _vulnerability_from_bundle(bundle) for bundle in visible_recent_fix_bundles(bundles)
        ]
        self.store.replace_models(
            "vulnerabilities",
            vulnerabilities,
            key=lambda item: item.internal_id,
        )
        return vulnerabilities

    def discover_recent_fixes(
        self,
        *,
        top: int = 20,
        lookback_days: int = 180,
        per_term: int = 5,
    ) -> list[SecurityEvidenceBundle]:
        prioritized = self.store.load_models("prioritized_mods", PrioritizedMod)
        if not prioritized:
            prioritized = self.prioritize_mods(top=top)
        targets = sorted(prioritized, key=lambda item: item.score, reverse=True)[:top]
        since_dt = since_for_lookback(lookback_days)
        since_iso = since_dt.isoformat().replace("+00:00", "Z")
        since_date = since_dt.date().isoformat()
        github = GitHubClient(
            token=self.settings.github_token,
            cache_directory=self.settings.cache_directory,
            timeout_seconds=self.settings.timeout_seconds,
            offline=self.offline,
            refresh=self.refresh,
        )
        bundles: list[SecurityEvidenceBundle] = []
        repositories: list[RepositoryResolution] = []
        try:
            for target in targets:
                repository = target.repository
                source = "prioritized_mods"
                evidence = target.source_url or target.issues_url or ""
                if repository is None:
                    candidates = [
                        RepositoryCandidate(
                            repository=str(raw.get("full_name")),
                            score=_score_prioritized_repository_candidate(target, raw),
                            source="github_search",
                        )
                        for raw in github.search_repositories(target.name, target.slug, [])
                    ]
                    resolution = resolve_repository(
                        _mod_from_prioritized(target),
                        overrides={},
                        candidates=candidates,
                    )
                    repository = resolution.repository
                else:
                    resolution = RepositoryResolution(
                        mod_project_id=target.project_id,
                        mod_name=target.name,
                        repository=repository,
                        confidence=100,
                        status="resolved",
                        source=source,
                        evidence=evidence,
                    )
                repositories.append(resolution)
                if repository is None:
                    continue
                recent_releases = github.list_recent_releases(repository, since=since_iso)
                recent_commits = github.list_recent_commits(repository, since=since_iso)
                bundles.extend(
                    _bundles_from_advisories(
                        target,
                        repository,
                        github.collect_global_advisories(repository),
                        lookback_since=since_dt,
                    )
                )
                bundles.extend(
                    _bundles_from_pull_requests(
                        target,
                        repository,
                        github.search_recent_pull_requests(
                            repository,
                            terms=RECENT_FIX_TERMS,
                            since_date=since_date,
                            per_term=per_term,
                        ),
                        github=github,
                        releases=recent_releases,
                    )
                )
                bundles.extend(
                    _bundles_from_commits(
                        target,
                        repository,
                        recent_commits,
                        github=github,
                        releases=recent_releases,
                    )
                )
                bundles.extend(_bundles_from_releases(target, repository, recent_releases))
                bundles.extend(
                    _bundles_from_issues(
                        target,
                        repository,
                        github.search_recent_issues(
                            repository,
                            terms=RECENT_FIX_TERMS,
                            since_date=since_date,
                            per_term=per_term,
                        ),
                    )
                )
        finally:
            github.close()

        scored = [
            score_security_bundle(
                bundle,
                lookback_since=since_dt,
                modpack_count=_target_modpack_count(targets, bundle.mod_project_id),
            )
            for bundle in _deduplicate_bundles(bundles)
        ]
        self.store.append_models(
            "repositories",
            repositories,
            key=lambda item: str(item.mod_project_id),
        )
        self.store.replace_models(
            "recent_fix_candidates",
            scored,
            key=_security_bundle_key,
        )
        self.store.replace_models(
            "security_signals",
            scored,
            key=_security_bundle_key,
        )
        vulnerabilities = [
            _vulnerability_from_bundle(bundle) for bundle in visible_recent_fix_bundles(scored)
        ]
        self.store.replace_models(
            "vulnerabilities",
            vulnerabilities,
            key=lambda item: item.internal_id,
        )
        return scored

    def correlate_recent_fixes(self) -> list[Finding]:
        return self.correlate()

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
        components = self._components_from_provider_versions(versions, provider=provider)
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
        *,
        dependency_version: ProviderVersion | None = None,
        dependency_project: ProviderProject | None = None,
    ) -> ModpackComponent:
        provider_project_id = (
            dependency_version.provider_project_id
            if dependency_version is not None
            else dependency.provider_project_id
        )
        if provider_project_id is None:
            provider_project_id = "unresolved"
        provider_version_id = dependency.provider_version_id or provider_project_id
        primary_file = _primary_provider_file(dependency_version) if dependency_version else None
        resolution_status = "resolved" if dependency_version is not None else "unresolved"
        return ModpackComponent(
            modpack_file_id=f"{version.provider}:{version.provider_version_id}",
            mod_project_id=f"{version.provider}:{provider_project_id}",
            mod_file_id=f"{version.provider}:{provider_version_id}",
            provider=dependency.provider,
            provider_project_id=provider_project_id,
            provider_version_id=dependency.provider_version_id,
            mod_name=dependency_project.title if dependency_project else None,
            mod_version=dependency_version.version_number if dependency_version else None,
            filename=primary_file.filename if primary_file else None,
            hashes=primary_file.hashes if primary_file else {},
            loaders=dependency_version.loaders if dependency_version else [],
            minecraft_versions=dependency_version.game_versions if dependency_version else [],
            source_url=dependency_project.source_url if dependency_project else None,
            resolution_status=resolution_status,
            requires_manual_review=resolution_status != "resolved",
            required=dependency.dependency_type == "required",
        )

    def _components_from_provider_versions(
        self,
        versions: list[ProviderVersion],
        *,
        provider: str,
    ) -> list[ModpackComponent]:
        dependencies = [
            dependency
            for version in versions
            for dependency in version.dependencies
            if dependency.provider_project_id
        ]
        if provider != "modrinth":
            return [
                self._component_from_provider_dependency(version, dependency)
                for version in versions
                for dependency in version.dependencies
                if dependency.provider_project_id
            ]

        version_ids = [
            dependency.provider_version_id
            for dependency in dependencies
            if dependency.provider_version_id
        ]
        provider_client = ProviderRegistry(
            self.settings,
            offline=self.offline,
            refresh=self.refresh,
        ).build_provider(provider)
        try:
            dependency_versions = provider_client.get_versions(version_ids)
            project_ids = [
                dependency_version.provider_project_id
                for dependency_version in dependency_versions.values()
            ]
            project_ids.extend(
                dependency.provider_project_id
                for dependency in dependencies
                if dependency.provider_project_id
            )
            dependency_projects = provider_client.get_projects(_unique_strings(project_ids))
        finally:
            provider_client.close()

        return [
            self._component_from_provider_dependency(
                version,
                dependency,
                dependency_version=dependency_versions.get(dependency.provider_version_id or ""),
                dependency_project=dependency_projects.get(
                    dependency_versions[dependency.provider_version_id].provider_project_id
                    if dependency.provider_version_id in dependency_versions
                    else dependency.provider_project_id or ""
                ),
            )
            for version in versions
            for dependency in version.dependencies
            if dependency.provider_project_id
        ]

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
            if component.resolution_status != "resolved":
                continue
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
                if affected_rule is None and fixed_rule is None:
                    continue
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
            recent_fix_candidates=self.store.load_models(
                "recent_fix_candidates",
                SecurityEvidenceBundle,
            ),
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


def _score_prioritized_repository_candidate(mod: PrioritizedMod, raw: dict[str, object]) -> int:
    score = 0
    full_name = str(raw.get("full_name") or "").lower()
    name = str(raw.get("name") or "").lower()
    if name in {mod.slug.lower(), mod.name.lower().replace(" ", "-")}:
        score += 60
    if mod.slug.lower() in full_name:
        score += 20
    if str(raw.get("archived")).lower() == "false":
        score += 5
    return score


def _mod_from_prioritized(mod: PrioritizedMod) -> ModProject:
    return ModProject(
        project_id=mod.project_id,
        provider=mod.provider,
        provider_project_id=mod.provider_project_id,
        name=mod.name,
        slug=mod.slug,
        download_count=mod.download_count,
        source_url=mod.source_url,
        issues_url=mod.issues_url,
    )


def _vulnerability_from_security_issue(
    mod: PrioritizedMod,
    repository: str,
    raw: dict[str, object],
) -> Vulnerability:
    title = str(raw.get("title") or "Untitled security signal")
    body = str(raw.get("body") or "")
    url = str(raw.get("html_url") or raw.get("url") or "")
    raw_matched_terms = raw.get("matched_terms", [])
    matched_terms = (
        [str(term) for term in raw_matched_terms]
        if isinstance(raw_matched_terms, (list, tuple, set))
        else []
    )
    description_parts = [body]
    if matched_terms:
        description_parts.append(f"Matched terms: {', '.join(matched_terms)}")
    if raw.get("state"):
        description_parts.append(f"GitHub issue state: {raw.get('state')}")
    text = "\n".join(description_parts)
    return Vulnerability(
        internal_id=f"issue:{url or raw.get('id') or title}",
        mod_project_id=mod.project_id,
        mod_name=mod.name,
        repository=repository,
        title=title,
        description=text,
        source_type=SourceType.ISSUE,
        source_url=url or f"https://github.com/{repository}/issues",
        impact_category=classify_impact(f"{title}\n{text}"),
        status="candidate",
        confidence=60,
        evidence=[url] if url else [f"https://github.com/{repository}/issues"],
        requires_manual_review=True,
    )


def _primary_provider_file(version: ProviderVersion | None) -> ProviderFile | None:
    if version is None or not version.files:
        return None
    return next((file for file in version.files if file.primary), version.files[0])


def _unique_strings(values: list[str]) -> list[str]:
    seen: set[str] = set()
    unique: list[str] = []
    for value in values:
        if value and value not in seen:
            seen.add(value)
            unique.append(value)
    return unique


def _bundles_from_advisories(
    mod: PrioritizedMod,
    repository: str,
    advisories: list[dict[str, object]],
    *,
    lookback_since: datetime,
) -> list[SecurityEvidenceBundle]:
    bundles: list[SecurityEvidenceBundle] = []
    for advisory in advisories:
        updated_at = str(advisory.get("updated_at") or advisory.get("published_at") or "")
        if updated_at and (parsed := _parse_datetime(updated_at)) and parsed < lookback_since:
            continue
        url = str(
            advisory.get("html_url") or advisory.get("url") or advisory.get("permalink") or ""
        )
        text = " ".join(
            str(advisory.get(field) or "")
            for field in ("summary", "description", "cve_id", "ghsa_id")
        )
        bundles.append(
            SecurityEvidenceBundle(
                mod_project_id=mod.project_id,
                mod_name=mod.name,
                repository=repository,
                issue_url=url or None,
                published_at=str(advisory.get("published_at") or ""),
                updated_at=updated_at or None,
                matched_terms=detect_matched_terms(text),
                fixed_versions=_as_string_list(advisory.get("fixed_versions")),
                affected_versions=_as_string_list(advisory.get("affected_versions")),
                reasons=["advisory"],
            )
        )
    return bundles


def _bundles_from_pull_requests(
    mod: PrioritizedMod,
    repository: str,
    pull_requests: list[dict[str, object]],
    *,
    github: GitHubClient,
    releases: list[dict[str, object]],
) -> list[SecurityEvidenceBundle]:
    bundles: list[SecurityEvidenceBundle] = []
    for item in pull_requests:
        url = str(item.get("html_url") or "")
        pull_number = _number_from_github_url(url)
        commits = github.list_pull_request_commits(repository, pull_number) if pull_number else []
        commit_sha = str(commits[0].get("sha") or "") if commits else ""
        commit_details = github.get_commit_details(repository, commit_sha) if commit_sha else {}
        changed_files, patches = _changed_files_and_patches(commit_details)
        release = _matching_release(releases, commit_sha, item)
        release_text = _release_text(release)
        body = str(item.get("body") or "")
        title = str(item.get("title") or "")
        fixed_versions = infer_fixed_versions(f"{title}\n{body}\n{release_text}")
        release_version = (
            str(release.get("tag_name") or release.get("name") or "") if release else ""
        )
        if release_version:
            fixed_versions = sorted(set([*fixed_versions, release_version]))
        patch_summary = summarize_patch(changed_files, patches)
        bundles.append(
            SecurityEvidenceBundle(
                mod_project_id=mod.project_id,
                mod_name=mod.name,
                repository=repository,
                pull_request_url=url or None,
                pull_request_merged_at=str(item.get("closed_at") or item.get("updated_at") or ""),
                commit_sha=commit_sha or None,
                commit_url=str(commit_details.get("html_url") or "") or None,
                release_url=str(release.get("html_url") or "") if release else None,
                release_version=release_version or None,
                published_at=str(item.get("created_at") or ""),
                updated_at=str(item.get("updated_at") or ""),
                matched_terms=sorted(
                    set(
                        [
                            *_as_string_list(item.get("matched_terms")),
                            *detect_matched_terms(f"{title}\n{body}\n{release_text}"),
                        ]
                    )
                ),
                changed_files=changed_files,
                patch_summary=patch_summary,
                maintainer_confirmation=str(item.get("author_association") or "").lower()
                in {"owner", "member", "collaborator"},
                fixed_versions=fixed_versions,
                reasons=["server_validation_diff"] if patch_adds_server_validation(patches) else [],
            )
        )
    return bundles


def _bundles_from_commits(
    mod: PrioritizedMod,
    repository: str,
    commits: list[dict[str, object]],
    *,
    github: GitHubClient,
    releases: list[dict[str, object]],
) -> list[SecurityEvidenceBundle]:
    bundles: list[SecurityEvidenceBundle] = []
    for item in commits:
        commit = item.get("commit") if isinstance(item.get("commit"), dict) else {}
        message = str(commit.get("message") or "") if isinstance(commit, dict) else ""
        matched_terms = detect_matched_terms(message)
        if not matched_terms:
            continue
        sha = str(item.get("sha") or "")
        details = github.get_commit_details(repository, sha) if sha else item
        changed_files, patches = _changed_files_and_patches(details)
        release = _matching_release(releases, sha, item)
        release_version = (
            str(release.get("tag_name") or release.get("name") or "") if release else ""
        )
        bundles.append(
            SecurityEvidenceBundle(
                mod_project_id=mod.project_id,
                mod_name=mod.name,
                repository=repository,
                commit_sha=sha or None,
                commit_url=str(item.get("html_url") or details.get("html_url") or "") or None,
                release_url=str(release.get("html_url") or "") if release else None,
                release_version=release_version or None,
                published_at=str(commit.get("committer", {}).get("date") or "")
                if isinstance(commit, dict)
                else None,
                updated_at=str(commit.get("committer", {}).get("date") or "")
                if isinstance(commit, dict)
                else None,
                matched_terms=matched_terms,
                changed_files=changed_files,
                patch_summary=summarize_patch(changed_files, patches),
                fixed_versions=[release_version] if release_version else [],
                reasons=["server_validation_diff"] if patch_adds_server_validation(patches) else [],
            )
        )
    return bundles


def _bundles_from_releases(
    mod: PrioritizedMod,
    repository: str,
    releases: list[dict[str, object]],
) -> list[SecurityEvidenceBundle]:
    bundles: list[SecurityEvidenceBundle] = []
    for release in releases:
        text = _release_text(release)
        matched_terms = detect_matched_terms(text)
        if not matched_terms:
            continue
        release_version = str(release.get("tag_name") or release.get("name") or "")
        bundles.append(
            SecurityEvidenceBundle(
                mod_project_id=mod.project_id,
                mod_name=mod.name,
                repository=repository,
                release_url=str(release.get("html_url") or "") or None,
                release_version=release_version or None,
                published_at=str(release.get("published_at") or release.get("created_at") or ""),
                updated_at=str(release.get("published_at") or release.get("created_at") or ""),
                matched_terms=matched_terms,
                fixed_versions=[release_version] if release_version else infer_fixed_versions(text),
                reasons=["release"],
            )
        )
    return bundles


def _bundles_from_issues(
    mod: PrioritizedMod,
    repository: str,
    issues: list[dict[str, object]],
) -> list[SecurityEvidenceBundle]:
    bundles: list[SecurityEvidenceBundle] = []
    for item in issues:
        text = (
            f"{item.get('title') or ''}\n{item.get('body') or ''}\n{item.get('state_reason') or ''}"
        )
        bundles.append(
            SecurityEvidenceBundle(
                mod_project_id=mod.project_id,
                mod_name=mod.name,
                repository=repository,
                issue_url=str(item.get("html_url") or "") or None,
                published_at=str(item.get("created_at") or ""),
                updated_at=str(item.get("updated_at") or ""),
                matched_terms=sorted(
                    set(
                        [
                            *_as_string_list(item.get("matched_terms")),
                            *detect_matched_terms(text),
                        ]
                    )
                ),
                maintainer_confirmation=str(item.get("author_association") or "").lower()
                in {"owner", "member", "collaborator"},
                reasons=[
                    str(label.get("name") or "")
                    for label in _as_dict_list(item.get("labels"))
                    if isinstance(label, dict)
                ],
            )
        )
    return bundles


def _vulnerability_from_bundle(bundle: SecurityEvidenceBundle) -> Vulnerability:
    source_url = (
        bundle.pull_request_url
        or bundle.commit_url
        or bundle.release_url
        or bundle.issue_url
        or f"https://github.com/{bundle.repository}"
    )
    return Vulnerability(
        internal_id=f"recent-fix:{source_url}",
        mod_project_id=bundle.mod_project_id,
        mod_name=bundle.mod_name,
        repository=bundle.repository,
        title=bundle.patch_summary or f"Recent security fix candidate in {bundle.repository}",
        description="\n".join(bundle.reasons),
        source_type=_source_type_from_bundle(bundle),
        source_url=source_url,
        impact_category=bundle.impact_category,
        attack_direction=bundle.attack_direction,
        prerequisites=bundle.prerequisites,
        affected_versions=bundle.affected_versions,
        fixed_versions=bundle.fixed_versions,
        status="candidate",
        confidence=bundle.confidence,
        evidence=[
            value
            for value in (
                bundle.issue_url,
                bundle.pull_request_url,
                bundle.commit_url,
                bundle.release_url,
            )
            if value
        ],
        requires_manual_review=bundle.requires_manual_review,
    )


def _source_type_from_bundle(bundle: SecurityEvidenceBundle) -> SourceType:
    if bundle.pull_request_url:
        return SourceType.PULL_REQUEST
    if bundle.commit_url:
        return SourceType.COMMIT
    if bundle.release_url:
        return SourceType.RELEASE
    return SourceType.ISSUE


def _security_bundle_key(bundle: SecurityEvidenceBundle) -> str:
    return "|".join(
        str(part or "")
        for part in (
            bundle.mod_project_id,
            bundle.issue_url,
            bundle.pull_request_url,
            bundle.commit_sha,
            bundle.release_url,
        )
    )


def _deduplicate_bundles(bundles: list[SecurityEvidenceBundle]) -> list[SecurityEvidenceBundle]:
    deduped: dict[str, SecurityEvidenceBundle] = {}
    for bundle in bundles:
        deduped[_security_bundle_key(bundle)] = bundle
    return list(deduped.values())


def _target_modpack_count(targets: list[PrioritizedMod], mod_project_id: int | str) -> int:
    for target in targets:
        if str(target.project_id) == str(mod_project_id):
            return target.modpack_count
    return 0


def _number_from_github_url(url: str) -> int | None:
    try:
        return int(url.rstrip("/").split("/")[-1])
    except ValueError:
        return None


def _changed_files_and_patches(details: dict[str, object]) -> tuple[list[str], list[str]]:
    files = details.get("files")
    if not isinstance(files, list):
        return [], []
    changed_files: list[str] = []
    patches: list[str] = []
    for file_payload in files:
        if not isinstance(file_payload, dict):
            continue
        filename = file_payload.get("filename")
        patch = file_payload.get("patch")
        if filename:
            changed_files.append(str(filename))
        if patch:
            patches.append(str(patch))
    return changed_files, patches


def _as_string_list(value: object) -> list[str]:
    if not isinstance(value, list):
        return []
    return [str(item) for item in value if item is not None]


def _as_dict_list(value: object) -> list[dict[str, object]]:
    if not isinstance(value, list):
        return []
    return [item for item in value if isinstance(item, dict)]


def _matching_release(
    releases: list[dict[str, object]],
    commit_sha: str,
    source: dict[str, object],
) -> dict[str, object]:
    source_text = " ".join(str(source.get(field) or "") for field in ("title", "body"))
    source_terms = detect_matched_terms(source_text)
    for release in releases:
        release_text = _release_text(release)
        if commit_sha and commit_sha in release_text:
            return release
        if source_terms and any(term in release_text.lower() for term in source_terms):
            return release
    return {}


def _release_text(release: dict[str, object]) -> str:
    return " ".join(str(release.get(field) or "") for field in ("name", "tag_name", "body"))


def _parse_datetime(value: str) -> datetime | None:
    from minemod_audit.security_discovery import parse_github_datetime

    return parse_github_datetime(value)
