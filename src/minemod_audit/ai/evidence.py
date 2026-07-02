from __future__ import annotations

import hashlib
import json
import re
from typing import Any

from minemod_audit.ai.schemas import GeminiAffectedModpack, GeminiEvidenceBundle, GeminiEvidenceItem
from minemod_audit.models import RecentSecurityFixCandidate

PRIORITY_TERMS = (
    "packet",
    "payload",
    "networking",
    "handler",
    "nbt",
    "itemstack",
    "inventory",
    "menu",
    "slot",
    "permission",
    "ownership",
    "distance",
    "dimension",
    "nonce",
    "pending request",
    "session state",
    "server-side validation",
    "currentlyediting",
)

URL_PATTERN = re.compile(r"https?://[^\s)>\]\"']+")


def build_evidence_bundle(
    candidate: RecentSecurityFixCandidate,
    *,
    max_input_chars: int = 30_000,
) -> GeminiEvidenceBundle:
    evidence = _dedupe_evidence(
        [
            GeminiEvidenceItem(
                evidence_id="changelog",
                kind="changelog",
                text=_compact(candidate.changelog_excerpt),
            ),
            GeminiEvidenceItem(
                evidence_id="patch_summary",
                kind="diff_or_patch_summary",
                text=_prioritized_text(candidate.patch_summary),
            ),
            GeminiEvidenceItem(
                evidence_id="issue_url",
                kind="issue",
                url=candidate.issue_url,
            ),
            GeminiEvidenceItem(
                evidence_id="pull_request_url",
                kind="pull_request",
                url=candidate.pull_request_url,
            ),
            GeminiEvidenceItem(
                evidence_id="commit_url",
                kind="commit",
                url=candidate.commit_url,
            ),
        ]
    )
    public_urls = _unique(
        [
            value
            for value in (
                candidate.repository,
                candidate.issue_url,
                candidate.pull_request_url,
                candidate.commit_url,
            )
            if value
        ]
    )
    bundle = GeminiEvidenceBundle(
        candidate_id=candidate.candidate_id,
        mod_name=candidate.mod_name,
        provider=candidate.provider,
        provider_project_id=candidate.provider_project_id,
        repository=candidate.repository,
        old_version=candidate.old_version,
        fixed_version=candidate.fixed_version,
        minecraft_version=candidate.minecraft_version,
        loader=candidate.loader,
        release_date=candidate.release_date,
        changed_files=_unique(candidate.changed_files),
        affected_modpack_count=len(candidate.affected_modpacks),
        affected_modpacks=[
            GeminiAffectedModpack.model_validate(item.model_dump(mode="json"))
            for item in candidate.affected_modpacks[:25]
        ],
        evidence=evidence,
        public_urls=public_urls,
    )
    return truncate_bundle(bundle, max_input_chars=max_input_chars)


def truncate_bundle(
    bundle: GeminiEvidenceBundle,
    *,
    max_input_chars: int,
) -> GeminiEvidenceBundle:
    if len(canonical_json(bundle)) <= max_input_chars:
        return bundle
    copy = bundle.model_copy(deep=True, update={"truncated": True})
    for item in copy.evidence:
        if item.text and len(canonical_json(copy)) > max_input_chars:
            item.text = _truncate_text(item.text, max(100, max_input_chars // 8))
    while len(canonical_json(copy)) > max_input_chars and copy.affected_modpacks:
        copy.affected_modpacks.pop()
        copy.affected_modpack_count = bundle.affected_modpack_count
    while len(canonical_json(copy)) > max_input_chars and copy.evidence:
        copy.evidence.pop()
    return copy


def evidence_hash(
    bundle: GeminiEvidenceBundle,
    *,
    model: str,
    prompt_version: str,
) -> str:
    payload = canonical_json(bundle) + model + prompt_version + bundle.schema_version
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def canonical_json(value: Any) -> str:
    if hasattr(value, "model_dump"):
        value = value.model_dump(mode="json")
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def urls_in_text(text: str) -> set[str]:
    return set(URL_PATTERN.findall(text))


def _dedupe_evidence(items: list[GeminiEvidenceItem]) -> list[GeminiEvidenceItem]:
    seen: set[tuple[str | None, str | None]] = set()
    result: list[GeminiEvidenceItem] = []
    for item in items:
        if not item.text and not item.url:
            continue
        normalized = (_compact(item.text or ""), item.url)
        if normalized in seen:
            continue
        seen.add(normalized)
        result.append(item)
    return result


def _prioritized_text(text: str) -> str:
    lines = [_compact(line) for line in text.splitlines() if _compact(line)]
    priority = [
        line
        for line in lines
        if any(term in line.lower().replace("_", "") for term in PRIORITY_TERMS)
    ]
    remainder = [line for line in lines if line not in priority]
    return "\n".join([*priority, *remainder])


def _compact(text: str) -> str:
    return " ".join(text.split())


def _truncate_text(text: str, limit: int) -> str:
    if len(text) <= limit:
        return text
    return f"{text[: max(0, limit - 20)]}...[truncated]"


def _unique(values: list[str]) -> list[str]:
    seen: set[str] = set()
    result: list[str] = []
    for value in values:
        if value not in seen:
            seen.add(value)
            result.append(value)
    return result
