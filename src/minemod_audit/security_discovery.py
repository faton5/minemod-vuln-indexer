from __future__ import annotations

import re
from datetime import UTC, datetime, timedelta

from minemod_audit.models import SecurityEvidenceBundle
from minemod_audit.security import classify_impact

RECENT_FIX_TERMS: tuple[str, ...] = (
    "fix dupe",
    "prevent duplication",
    "validate packet",
    "server-side validation",
    "do not trust client",
    "permission check",
    "ownership check",
    "distance check",
    "arbitrary item",
    "crafted packet",
    "malformed packet",
    "NBT validation",
    "replay",
    "race condition",
    "security fix",
    "exploit fix",
)

REJECTED_TERMS: tuple[str, ...] = (
    "invalid",
    "duplicate",
    "wontfix",
    "won't fix",
    "question",
    "support",
    "not planned",
)

VISUAL_ONLY_TERMS: tuple[str, ...] = ("visual", "render", "shader", "texture", "client crash")

SERVER_VALIDATION_TERMS: tuple[str, ...] = (
    "permission",
    "ownership",
    "distance",
    "item type",
    "quantity",
    "slot",
    "dimension",
    "nonce",
    "packet",
    "server-side",
    "validate",
    "validation",
)


def since_for_lookback(days: int, *, now: datetime | None = None) -> datetime:
    current = now or datetime.now(UTC)
    if current.tzinfo is None:
        current = current.replace(tzinfo=UTC)
    return current - timedelta(days=days)


def parse_github_datetime(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None


def detect_matched_terms(text: str, terms: tuple[str, ...] = RECENT_FIX_TERMS) -> list[str]:
    normalized = text.lower()
    return sorted({term for term in terms if term.lower() in normalized})


def summarize_patch(changed_files: list[str], patches: list[str]) -> str | None:
    haystack = "\n".join(patches).lower()
    detected = [term for term in SERVER_VALIDATION_TERMS if term in haystack]
    if not changed_files and not detected:
        return None
    parts = []
    if changed_files:
        parts.append(f"Changed files: {', '.join(changed_files[:8])}")
    if detected:
        parts.append(f"Validation-related additions: {', '.join(sorted(set(detected)))}")
    return ". ".join(parts)


def patch_adds_server_validation(patches: list[str]) -> bool:
    additions = "\n".join(
        line[1:].lower()
        for patch in patches
        for line in patch.splitlines()
        if line.startswith("+") and not line.startswith("+++")
    )
    return any(term in additions for term in SERVER_VALIDATION_TERMS)


def infer_fixed_versions(text: str) -> list[str]:
    patterns = [
        r"\bfixed in\s+v?([0-9][A-Za-z0-9.+_-]*)",
        r"\breleased in\s+v?([0-9][A-Za-z0-9.+_-]*)",
    ]
    versions: list[str] = []
    for pattern in patterns:
        versions.extend(
            version.rstrip(".,;:") for version in re.findall(pattern, text, flags=re.IGNORECASE)
        )
    return sorted(set(versions))


def score_security_bundle(
    bundle: SecurityEvidenceBundle,
    *,
    lookback_since: datetime,
    modpack_count: int = 0,
) -> SecurityEvidenceBundle:
    score = 0
    reasons: list[str] = []
    text = " ".join(
        [
            bundle.patch_summary or "",
            " ".join(bundle.matched_terms),
            bundle.issue_url or "",
            bundle.pull_request_url or "",
            bundle.release_url or "",
        ]
    ).lower()

    if "advisory" in bundle.reasons:
        score += 40
        reasons.append("+40 official advisory")
    if bundle.pull_request_url and bundle.pull_request_merged_at:
        score += 30
        reasons.append("+30 merged pull request")
    if bundle.release_url:
        score += 25
        reasons.append("+25 release mentions fix")
    if bundle.patch_summary and any(
        term in bundle.patch_summary.lower() for term in SERVER_VALIDATION_TERMS
    ):
        score += 20
        reasons.append("+20 server-side validation diff")
    if bundle.maintainer_confirmation:
        score += 15
        reasons.append("+15 maintainer confirmation")
    if bundle.fixed_versions:
        score += 10
        reasons.append("+10 fixed version identifiable")
    if modpack_count > 1:
        score += 10
        reasons.append("+10 present in multiple modpacks")

    evidence_count = sum(
        bool(value)
        for value in (
            bundle.pull_request_url,
            bundle.commit_url,
            bundle.release_url,
            "advisory" in bundle.reasons,
        )
    )
    issue_only = bool(bundle.issue_url) and evidence_count == 0
    if issue_only:
        score -= 40
        reasons.append("-40 simple keyword-only issue")

    updated_at = parse_github_datetime(bundle.updated_at or bundle.published_at)
    if updated_at and updated_at < lookback_since:
        score -= 30
        reasons.append("-30 stale issue outside lookback")
    if any(term in text for term in REJECTED_TERMS):
        score -= 25
        reasons.append("-25 invalid duplicate wontfix or support signal")
    if not (bundle.pull_request_url or bundle.commit_url or bundle.release_url):
        score -= 25
        reasons.append("-25 no linked PR commit or release")
    if any(term in text for term in VISUAL_ONLY_TERMS):
        score -= 20
        reasons.append("-20 visual or client-only bug")
    if not (bundle.affected_versions or bundle.fixed_versions):
        score -= 15
        reasons.append("-15 no affected or fixed version")

    if issue_only:
        score = min(score, 30)

    status = "weak_signal"
    if any(term in text for term in REJECTED_TERMS):
        status = "rejected"
    elif score >= 70 and evidence_count >= 2:
        status = "actionable"
    elif 50 <= score <= 69:
        status = "promising"

    return bundle.model_copy(
        update={
            "confidence": max(0, min(100, score)),
            "status": status,
            "reasons": [*bundle.reasons, *reasons],
            "requires_manual_review": status != "actionable",
            "impact_category": classify_impact(text),
        }
    )


def visible_recent_fix_bundles(
    bundles: list[SecurityEvidenceBundle],
    *,
    include_weak: bool = False,
) -> list[SecurityEvidenceBundle]:
    if include_weak:
        return [bundle for bundle in bundles if bundle.status != "rejected"]
    return [bundle for bundle in bundles if bundle.status in {"actionable", "promising"}]
