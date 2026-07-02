from __future__ import annotations

import re
from collections import Counter, defaultdict
from collections.abc import Iterable
from datetime import UTC, datetime

from packaging.version import InvalidVersion, Version

from minemod_audit.models import (
    CanonicalMod,
    Modpack,
    ModpackComponent,
    ModpackRelease,
    ModProject,
    ReleaseDiffCandidate,
    ReleaseLagFinding,
    ReleaseLagLibrary,
)
from minemod_audit.repository import extract_github_repository

PRIORITY_PATH_TERMS = (
    "network",
    "packet",
    "payload",
    "handler",
    "itemstack",
    "inventory",
    "container",
    "slot",
    "nbt",
    "permission",
    "command",
    "owner",
    "distance",
    "teleport",
    "dimension",
    "reward",
    "trade",
    "recipe",
    "entity",
    "blockentity",
    "session",
)

VALIDATION_TERMS = (
    "permission",
    "sender",
    "player",
    "identity",
    "distance",
    "dimension",
    "owner",
    "ownership",
    "slot",
    "quantity",
    "amount",
    "type",
    "request",
    "server request",
    "nonce",
    "already",
    "processed",
    "client",
    "server-side",
    "serverside",
    "rebuild",
    "currentlyediting",
    "unsolicited",
)


def build_canonical_mods(
    *,
    mods: Iterable[ModProject],
    components: Iterable[ModpackComponent],
) -> list[CanonicalMod]:
    grouped: dict[str, _CanonicalBuilder] = {}
    for mod in mods:
        provider, provider_id = _provider_identity(
            mod.provider, mod.provider_project_id, mod.project_id
        )
        github_repository = _normalized_github_repository(mod.source_url or mod.issues_url)
        canonical_id = _canonical_id(github_repository, provider, provider_id)
        builder = grouped.setdefault(canonical_id, _CanonicalBuilder(canonical_id))
        builder.add(
            provider=provider,
            provider_id=provider_id,
            alias_values=[mod.name, mod.slug],
            github_repository=github_repository,
            loaders=mod.categories,
            minecraft_branches=mod.latest_versions,
        )

    for component in components:
        provider, provider_id = _provider_identity(
            component.provider,
            component.provider_project_id,
            component.mod_project_id,
        )
        github_repository = _normalized_github_repository(component.source_url)
        canonical_id = _canonical_id(github_repository, provider, provider_id)
        builder = grouped.setdefault(canonical_id, _CanonicalBuilder(canonical_id))
        builder.add(
            provider=provider,
            provider_id=provider_id,
            alias_values=[component.mod_name],
            github_repository=github_repository,
            loaders=component.loaders,
            minecraft_branches=component.minecraft_versions,
        )

    return [builder.build() for builder in sorted(grouped.values(), key=lambda item: item.key)]


def rank_libraries_by_modpack_releases(
    *,
    components: Iterable[ModpackComponent],
    canonicals: Iterable[CanonicalMod],
    limit: int | None = None,
) -> list[ReleaseLagLibrary]:
    canonical_by_provider_id = _canonical_by_provider_id(canonicals)
    release_ids_by_canonical: dict[str, set[str]] = defaultdict(set)
    pack_ids_by_canonical: dict[str, set[str]] = defaultdict(set)
    names_by_canonical: dict[str, Counter[str]] = defaultdict(Counter)
    repository_by_canonical = {
        canonical.canonical_id: canonical.github_repository for canonical in canonicals
    }

    for component in components:
        canonical_id = _component_canonical_id(component, canonical_by_provider_id)
        release_id = str(component.modpack_file_id)
        release_ids_by_canonical[canonical_id].add(release_id)
        pack_ids_by_canonical[canonical_id].add(
            release_id.split(":", maxsplit=1)[-1].split("-", 1)[0]
        )
        if component.mod_name:
            names_by_canonical[canonical_id][component.mod_name] += 1

    ranked = [
        ReleaseLagLibrary(
            canonical_mod_id=canonical_id,
            mod_name=names_by_canonical[canonical_id].most_common(1)[0][0]
            if names_by_canonical[canonical_id]
            else canonical_id,
            modpack_release_count=len(release_ids),
            modpack_count=len(pack_ids_by_canonical[canonical_id]),
            github_repository=repository_by_canonical.get(canonical_id),
        )
        for canonical_id, release_ids in release_ids_by_canonical.items()
    ]
    ranked.sort(
        key=lambda item: (item.modpack_release_count, item.modpack_count, item.mod_name.lower()),
        reverse=True,
    )
    return ranked[:limit] if limit is not None else ranked


def classify_release_diff(
    *,
    canonical_mod_id: str,
    old_version: str,
    new_version: str,
    old_tag: str | None,
    new_tag: str | None,
    changed_files: list[str],
    patches: list[str],
    commit_message: str,
    published_at: str | None,
    minecraft_branch: str | None,
    loader: str | None,
    fixed_commit: str | None,
) -> ReleaseDiffCandidate:
    del commit_message
    relevant_patches = [
        patch
        for patch in patches
        if _patch_has_priority_signal(patch) or _files_have_priority_signal(changed_files)
    ]
    evidence = _diff_evidence(changed_files, relevant_patches)
    category = _category_from_evidence(evidence)
    confidence = _confidence_from_evidence(evidence, relevant_patches, changed_files)
    explanation = _explain_evidence(evidence)
    return ReleaseDiffCandidate(
        canonical_mod_id=canonical_mod_id,
        old_version=old_version,
        new_version=new_version,
        old_tag=old_tag,
        new_tag=new_tag,
        changed_files=changed_files,
        relevant_patch_sections=relevant_patches,
        category=category,
        explanation=explanation,
        confidence=confidence,
        fixed_commit=fixed_commit,
        published_at=published_at,
        minecraft_branch=minecraft_branch,
        loader=loader,
    )


def correlate_release_lag(
    *,
    candidates: Iterable[ReleaseDiffCandidate],
    canonicals: Iterable[CanonicalMod],
    components: Iterable[ModpackComponent],
    modpacks: Iterable[Modpack],
    releases: Iterable[ModpackRelease],
    now: datetime | None = None,
) -> list[ReleaseLagFinding]:
    current_time = now or datetime.now(UTC)
    canonical_by_provider_id = _canonical_by_provider_id(canonicals)
    components_list = list(components)
    releases_by_id = {str(release.file_id): release for release in releases}
    modpacks_by_id = {str(modpack.project_id): modpack for modpack in modpacks}
    latest_release_by_pack = _latest_release_by_pack(releases_by_id.values())
    available_versions = _available_versions_by_context(components_list, canonical_by_provider_id)
    findings: list[ReleaseLagFinding] = []

    for candidate in candidates:
        new_version_available = (
            candidate.new_version
            in available_versions[
                (
                    candidate.canonical_mod_id,
                    candidate.minecraft_branch or "",
                    candidate.loader or "",
                )
            ]
        )
        for component in components_list:
            if component.resolution_status != "resolved":
                continue
            component_canonical_id = _component_canonical_id(component, canonical_by_provider_id)
            if component_canonical_id != candidate.canonical_mod_id:
                continue
            if component.mod_version != candidate.old_version:
                continue
            release = releases_by_id.get(str(component.modpack_file_id))
            if release is None:
                continue
            if (
                candidate.minecraft_branch
                and release.minecraft_version != candidate.minecraft_branch
            ):
                continue
            if candidate.loader and release.loader != candidate.loader:
                continue
            modpack = modpacks_by_id.get(str(release.modpack_project_id))
            latest_pack_release = latest_release_by_pack.get(
                str(release.modpack_project_id)
            ) == str(release.file_id)
            status = _release_lag_status(
                new_version_available=new_version_available,
                latest_pack_release=latest_pack_release,
                confidence=candidate.confidence,
            )
            findings.append(
                ReleaseLagFinding(
                    canonical_mod_id=candidate.canonical_mod_id,
                    mod_name=component.mod_name or candidate.canonical_mod_id,
                    modpack_name=modpack.name if modpack else "unknown",
                    modpack_release=release.display_name,
                    old_version=candidate.old_version,
                    new_version=candidate.new_version,
                    status=status,
                    days_since_fix=_days_since(candidate.published_at, current_time),
                    latest_pack_release=latest_pack_release,
                    minecraft_branch=release.minecraft_version,
                    loader=release.loader,
                    confidence=candidate.confidence,
                    evidence_urls=[
                        value
                        for value in (
                            candidate.fixed_commit,
                            candidate.new_tag,
                        )
                        if value
                    ],
                    requires_manual_review=status != "confirmed_lag",
                )
            )
    return findings


def sorted_release_versions(versions: Iterable[str]) -> list[str]:
    return sorted(set(versions), key=_version_sort_key)


def matching_tag(version: str, tags: Iterable[str]) -> str | None:
    normalized = _normalize_version_token(version)
    for tag in tags:
        if _normalize_version_token(tag) == normalized:
            return tag
    for tag in tags:
        if normalized and normalized in _normalize_version_token(tag):
            return tag
    return None


class _CanonicalBuilder:
    def __init__(self, key: str) -> None:
        self.key = key
        self.github_repository: str | None = (
            key.removeprefix("github:") if key.startswith("github:") else None
        )
        self.curseforge_project_ids: set[str] = set()
        self.modrinth_project_ids: set[str] = set()
        self.aliases: set[str] = set()
        self.loaders: set[str] = set()
        self.minecraft_branches: set[str] = set()

    def add(
        self,
        *,
        provider: str | None,
        provider_id: str,
        alias_values: Iterable[str | None],
        github_repository: str | None,
        loaders: Iterable[str],
        minecraft_branches: Iterable[str],
    ) -> None:
        if github_repository:
            self.github_repository = github_repository
        if provider == "curseforge":
            self.curseforge_project_ids.add(provider_id)
        elif provider == "modrinth":
            self.modrinth_project_ids.add(provider_id)
        self.aliases.update(value for value in alias_values if value)
        self.loaders.update(value for value in loaders if value)
        self.minecraft_branches.update(value for value in minecraft_branches if value)

    def build(self) -> CanonicalMod:
        return CanonicalMod(
            canonical_id=self.key,
            github_repository=self.github_repository,
            curseforge_project_ids=sorted(self.curseforge_project_ids),
            modrinth_project_ids=sorted(self.modrinth_project_ids),
            aliases=sorted(self.aliases),
            loaders=sorted(self.loaders),
            minecraft_branches=sorted(self.minecraft_branches),
        )


def _canonical_id(github_repository: str | None, provider: str | None, provider_id: str) -> str:
    if github_repository:
        return f"github:{github_repository}"
    return f"provider:{provider or 'unknown'}:{provider_id}"


def _normalized_github_repository(url: str | None) -> str | None:
    repository = extract_github_repository(url)
    return repository.lower() if repository else None


def _provider_identity(
    provider: str | None,
    provider_project_id: str | None,
    project_id: str | int,
) -> tuple[str | None, str]:
    if provider and provider_project_id:
        return provider, provider_project_id
    raw_project_id = str(project_id)
    if ":" in raw_project_id:
        parsed_provider, parsed_id = raw_project_id.split(":", maxsplit=1)
        return provider or parsed_provider, provider_project_id or parsed_id
    return provider, provider_project_id or raw_project_id


def _canonical_by_provider_id(canonicals: Iterable[CanonicalMod]) -> dict[tuple[str, str], str]:
    mapping: dict[tuple[str, str], str] = {}
    for canonical in canonicals:
        for project_id in canonical.curseforge_project_ids:
            mapping[("curseforge", project_id)] = canonical.canonical_id
        for project_id in canonical.modrinth_project_ids:
            mapping[("modrinth", project_id)] = canonical.canonical_id
    return mapping


def _component_canonical_id(
    component: ModpackComponent,
    canonical_by_provider_id: dict[tuple[str, str], str],
) -> str:
    provider, provider_id = _provider_identity(
        component.provider,
        component.provider_project_id,
        component.mod_project_id,
    )
    return canonical_by_provider_id.get(
        (provider or "unknown", provider_id),
        _canonical_id(_normalized_github_repository(component.source_url), provider, provider_id),
    )


def _files_have_priority_signal(changed_files: list[str]) -> bool:
    return any(
        term in file_name.lower().replace("_", "").replace("-", "")
        for file_name in changed_files
        for term in PRIORITY_PATH_TERMS
    )


def _patch_has_priority_signal(patch: str) -> bool:
    normalized = patch.lower().replace("_", "").replace("-", "")
    return any(term.replace("_", "").replace("-", "") in normalized for term in VALIDATION_TERMS)


def _diff_evidence(changed_files: list[str], patches: list[str]) -> set[str]:
    joined = "\n".join(patches).lower()
    compact = joined.replace("_", "").replace("-", "")
    evidence: set[str] = set()
    if "currentlyediting" in compact:
        evidence.add("currentlyEditing session state")
    if "server request" in joined or ("request" in compact and "response" in compact):
        evidence.add("client response compared with server request")
    if "unsolicited" in joined or ("null" in compact and "return" in compact):
        evidence.add("unsolicited client response rejection")
    if "rebuild" in compact and "server" in compact:
        evidence.add("server-side state reconstruction")
    if "permission" in compact:
        evidence.add("permission verification")
    if "distance" in compact:
        evidence.add("distance verification")
    if "dimension" in compact:
        evidence.add("dimension verification")
    if "slot" in compact or "quantity" in compact or "amount" in compact:
        evidence.add("slot quantity or type validation")
    if any("nbt" in file_name.lower() for file_name in changed_files):
        evidence.add("NBT-sensitive file changed")
    return evidence


def _category_from_evidence(evidence: set[str]) -> str:
    if any(
        "session" in item or "server request" in item or "unsolicited" in item for item in evidence
    ):
        return "client_state_validation"
    if any("permission" in item for item in evidence):
        return "permission_validation"
    if any("distance" in item or "dimension" in item for item in evidence):
        return "world_state_validation"
    if any("slot" in item or "NBT" in item for item in evidence):
        return "inventory_or_nbt_validation"
    return "manual_review"


def _confidence_from_evidence(
    evidence: set[str],
    relevant_patches: list[str],
    changed_files: list[str],
) -> int:
    score = 20
    score += min(60, len(evidence) * 15)
    if relevant_patches:
        score += 10
    if _files_have_priority_signal(changed_files):
        score += 10
    return min(100, score)


def _explain_evidence(evidence: set[str]) -> str:
    if not evidence:
        return "No high-priority validation pattern was detected; manual review required."
    return "; ".join(sorted(evidence))


def _latest_release_by_pack(releases: Iterable[ModpackRelease]) -> dict[str, str]:
    latest: dict[str, ModpackRelease] = {}
    for release in releases:
        pack_id = str(release.modpack_project_id)
        current = latest.get(pack_id)
        if current is None or _date_sort_key(release.release_date) >= _date_sort_key(
            current.release_date
        ):
            latest[pack_id] = release
    return {pack_id: str(release.file_id) for pack_id, release in latest.items()}


def _available_versions_by_context(
    components: Iterable[ModpackComponent],
    canonical_by_provider_id: dict[tuple[str, str], str],
) -> dict[tuple[str, str, str], set[str]]:
    available: dict[tuple[str, str, str], set[str]] = defaultdict(set)
    for component in components:
        if not component.mod_version:
            continue
        canonical_id = _component_canonical_id(component, canonical_by_provider_id)
        branches = component.minecraft_versions or [""]
        loaders = component.loaders or [""]
        for branch in branches:
            for loader in loaders:
                available[(canonical_id, branch, loader)].add(component.mod_version)
    return available


def _release_lag_status(
    *,
    new_version_available: bool,
    latest_pack_release: bool,
    confidence: int,
) -> str:
    if not new_version_available:
        return "manual_review"
    if latest_pack_release and confidence >= 70:
        return "confirmed_lag"
    if confidence >= 50:
        return "likely_lag"
    return "manual_review"


def _days_since(published_at: str | None, now: datetime) -> int | None:
    if not published_at:
        return None
    try:
        published = datetime.fromisoformat(published_at.replace("Z", "+00:00"))
    except ValueError:
        return None
    if published.tzinfo is None:
        published = published.replace(tzinfo=UTC)
    return max(0, (now - published).days)


def _date_sort_key(value: str | None) -> datetime:
    if not value:
        return datetime.min.replace(tzinfo=UTC)
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return datetime.min.replace(tzinfo=UTC)
    if parsed.tzinfo is None:
        return parsed.replace(tzinfo=UTC)
    return parsed


def _version_sort_key(value: str) -> tuple[int, Version | str]:
    normalized = _normalize_version_token(value)
    try:
        return (1, Version(normalized))
    except InvalidVersion:
        return (0, normalized)


def _normalize_version_token(value: str) -> str:
    normalized = value.strip().lower()
    normalized = normalized.removeprefix("refs/tags/")
    normalized = normalized.removeprefix("v")
    normalized = re.sub(r"^[a-z]+-", "", normalized)
    return normalized
