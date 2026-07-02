from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field
from datetime import UTC, datetime

from minemod_audit.models import (
    AffectedModpack,
    Modpack,
    ModpackComponent,
    ModpackRelease,
    RecentSecurityFixCandidate,
)

INTERESTING_CHANGELOG_TERMS = (
    "fix exploit",
    "fix dupe",
    "duplication",
    "security fix",
    "permission fix",
    "packet validation",
    "server-side validation",
    "invalid slot",
    "crafted packet",
    "nbt fix",
    "server-side",
    "currentlyediting",
    "unauthorized",
    "bypass",
    "crash caused by packet",
    "trust client",
    "ownership check",
    "distance check",
)

EXPLICIT_SECURITY_TERMS = (
    "exploit",
    "dupe",
    "duplication",
    "security",
)

SERVER_VALIDATION_TERMS = (
    "server-side",
    "currentlyediting",
    "request",
    "sender",
    "player",
    "permission",
    "ownership",
    "distance",
    "dimension",
    "slot",
    "packet",
    "nbt",
    "validate",
    "validation",
)

VISUAL_ONLY_TERMS = ("render", "shader", "texture", "visual", "client crash")


@dataclass(frozen=True)
class RecentFixRelease:
    mod_project_id: str
    mod_name: str
    old_version: str
    fixed_version: str
    release_date: str | None
    changelog: str
    provider: str = "curseforge"
    provider_project_id: str = ""
    old_file_id: str | None = None
    new_file_id: str | None = None
    minecraft_version: str | None = None
    loader: str | None = None
    repository: str | None = None
    issue_url: str | None = None
    pull_request_url: str | None = None
    commit_url: str | None = None
    changed_files: list[str] = field(default_factory=list)
    patches: list[str] = field(default_factory=list)
    maintainer_confirmed: bool = False


def classify_recent_fix(
    release: RecentFixRelease,
    *,
    modpack_presence_count: int = 0,
    latest_modpack_still_affected: bool = False,
) -> RecentSecurityFixCandidate:
    text = f"{release.changelog}\n{' '.join(release.changed_files)}\n{''.join(release.patches)}"
    normalized = text.lower()
    score = 0

    if any(term in normalized for term in EXPLICIT_SECURITY_TERMS):
        score += 30
    elif is_interesting_changelog(release.changelog):
        score += 25
    if release.pull_request_url or release.commit_url:
        score += 25
    if _has_server_validation_diff(release.patches):
        score += 20
    if release.issue_url or release.maintainer_confirmed:
        score += 15
    if release.fixed_version:
        score += 15
    if modpack_presence_count > 1:
        score += 10
    if latest_modpack_still_affected:
        score += 10

    if _is_plain_bugfix_without_proof(normalized):
        score -= 30
    if not release.old_version:
        score -= 25
    if any(term in normalized for term in VISUAL_ONLY_TERMS):
        score -= 20

    score = max(0, min(100, score))
    category = _category(score, normalized)
    candidate = RecentSecurityFixCandidate(
        candidate_id=_candidate_id(release),
        mod_name=release.mod_name,
        repository=release.repository,
        provider=release.provider,
        provider_project_id=release.provider_project_id
        or release.mod_project_id.split(":", maxsplit=1)[-1],
        old_file_id=release.old_file_id,
        new_file_id=release.new_file_id,
        old_version=release.old_version,
        fixed_version=release.fixed_version,
        minecraft_version=release.minecraft_version,
        loader=release.loader,
        release_date=release.release_date,
        changelog_excerpt=_excerpt(release.changelog),
        issue_url=release.issue_url,
        pull_request_url=release.pull_request_url,
        commit_url=release.commit_url,
        changed_files=release.changed_files,
        patch_summary=_patch_summary(release),
        potential_impact=_potential_impact(normalized),
        prerequisites=_prerequisites(normalized),
        public_exploit_information=public_exploit_information_level(text),
        confidence=score,
        category=category,
        requires_manual_review=category not in {"confirmed_public_fix", "likely_security_fix"},
    )
    return candidate


def correlate_affected_modpacks(
    *,
    candidate: RecentSecurityFixCandidate,
    components: list[ModpackComponent],
    modpacks: list[Modpack],
    releases: list[ModpackRelease],
    now: datetime | None = None,
) -> list[AffectedModpack]:
    current_time = now or datetime.now(UTC)
    releases_by_id = {str(release.file_id): release for release in releases}
    modpacks_by_id = {str(modpack.project_id): modpack for modpack in modpacks}
    latest_release_by_pack = _latest_release_by_pack(releases)
    affected: list[AffectedModpack] = []
    for component in components:
        if not _component_matches_candidate(component, candidate):
            continue
        release = releases_by_id.get(str(component.modpack_file_id))
        if release is None:
            continue
        modpack = modpacks_by_id.get(str(release.modpack_project_id))
        latest_pack_release = latest_release_by_pack.get(str(release.modpack_project_id)) == str(
            release.file_id
        )
        affected.append(
            AffectedModpack(
                modpack=modpack.name if modpack else "unknown",
                modpack_release=release.display_name,
                installed_version=component.mod_version or str(component.mod_file_id),
                fixed_version=candidate.fixed_version,
                same_minecraft_loader=_same_minecraft_loader(component, release, candidate),
                latest_pack_release=latest_pack_release,
                days_since_fix=_days_since(candidate.release_date, current_time),
                download_count=modpack.download_count if modpack else 0,
            )
        )
    return affected


def public_exploit_information_level(text: str) -> str:
    normalized = text.lower()
    if "poc" in normalized or "proof of concept" in normalized:
        return "public_poc"
    if "steps to reproduce" in normalized or "reproduction steps" in normalized:
        return "public_reproduction_steps"
    if any(term in normalized for term in ("request", "packet", "nbt", "permission", "bypass")):
        return "technical_description"
    if any(term in normalized for term in ("exploit", "dupe", "duplication", "security")):
        return "impact_only"
    return "none"


def is_interesting_changelog(text: str) -> bool:
    normalized = text.lower()
    return any(term in normalized for term in INTERESTING_CHANGELOG_TERMS)


def linked_reference_numbers(text: str) -> list[int]:
    return sorted({int(match) for match in re.findall(r"#(\d+)", text)})


def linked_sha(text: str) -> str | None:
    match = re.search(r"\b[0-9a-f]{7,40}\b", text.lower())
    return match.group(0) if match else None


def _component_matches_candidate(
    component: ModpackComponent,
    candidate: RecentSecurityFixCandidate,
) -> bool:
    if str(component.mod_project_id) != f"{candidate.provider}:{candidate.provider_project_id}":
        return False
    exact_old_file = bool(candidate.old_file_id) and str(component.mod_file_id) == str(
        candidate.old_file_id
    )
    exact_old_version = (
        bool(candidate.old_version) and component.mod_version == candidate.old_version
    )
    return exact_old_file or exact_old_version


def _same_minecraft_loader(
    component: ModpackComponent,
    release: ModpackRelease,
    candidate: RecentSecurityFixCandidate,
) -> bool:
    minecraft_ok = not candidate.minecraft_version or candidate.minecraft_version in {
        release.minecraft_version,
        *component.minecraft_versions,
    }
    loader_ok = not candidate.loader or candidate.loader in {release.loader, *component.loaders}
    return minecraft_ok and loader_ok


def _has_server_validation_diff(patches: list[str]) -> bool:
    additions = "\n".join(
        line[1:].lower().replace("_", "")
        for patch in patches
        for line in patch.splitlines()
        if line.startswith("+") and not line.startswith("+++")
    )
    return any(term.replace("_", "") in additions for term in SERVER_VALIDATION_TERMS)


def _is_plain_bugfix_without_proof(normalized: str) -> bool:
    return "bug fix" in normalized and not any(
        term in normalized for term in (*EXPLICIT_SECURITY_TERMS, "packet", "nbt", "permission")
    )


def _category(score: int, normalized: str) -> str:
    if any(term in normalized for term in VISUAL_ONLY_TERMS):
        return "unrelated"
    if score >= 70:
        return "confirmed_public_fix"
    if score >= 55:
        return "likely_security_fix"
    if score >= 35:
        return "interesting_bugfix"
    return "insufficient_evidence"


def _candidate_id(release: RecentFixRelease) -> str:
    payload = "|".join(
        [
            release.mod_project_id,
            release.old_version,
            release.fixed_version,
            release.new_file_id or "",
        ]
    )
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()[:16]


def _excerpt(text: str, *, limit: int = 500) -> str:
    compact = " ".join(text.split())
    if len(compact) <= limit:
        return compact
    return f"{compact[: limit - 3]}..."


def _patch_summary(release: RecentFixRelease) -> str:
    if release.changed_files:
        return f"Changed files: {', '.join(release.changed_files[:8])}"
    if is_interesting_changelog(release.changelog):
        return "Interesting changelog security or logic-fix wording"
    return "No linked diff available"


def _potential_impact(normalized: str) -> str:
    if "dupe" in normalized or "duplication" in normalized:
        return "Possible item or state duplication fixed publicly."
    if "nbt" in normalized or "packet" in normalized or "trust client" in normalized:
        return "Possible server-side trust boundary issue fixed publicly."
    if "permission" in normalized or "unauthorized" in normalized or "bypass" in normalized:
        return "Possible permission or authorization bypass fixed publicly."
    if "crash" in normalized:
        return "Possible denial-of-service or crash vector fixed publicly."
    return "Public changelog suggests a potentially relevant logic fix."


def _prerequisites(normalized: str) -> str | None:
    if "packet" in normalized or "client" in normalized:
        return "Player or client able to send the affected interaction."
    if "permission" in normalized:
        return "Player reaches an action previously missing a permission check."
    return None


def _latest_release_by_pack(releases: list[ModpackRelease]) -> dict[str, str]:
    latest: dict[str, ModpackRelease] = {}
    for release in releases:
        pack_id = str(release.modpack_project_id)
        current = latest.get(pack_id)
        if current is None or _date_key(release.release_date) >= _date_key(current.release_date):
            latest[pack_id] = release
    return {pack_id: str(release.file_id) for pack_id, release in latest.items()}


def _days_since(published_at: str | None, now: datetime) -> int | None:
    if not published_at:
        return None
    published = _date_key(published_at)
    return max(0, (now - published).days)


def _date_key(value: str | None) -> datetime:
    if not value:
        return datetime.min.replace(tzinfo=UTC)
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return datetime.min.replace(tzinfo=UTC)
    if parsed.tzinfo is None:
        return parsed.replace(tzinfo=UTC)
    return parsed
