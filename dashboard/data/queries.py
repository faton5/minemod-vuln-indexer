from __future__ import annotations

import csv
import io
import json
from collections import Counter
from collections.abc import Iterable
from pathlib import Path
from typing import Any

import streamlit as st
from sqlalchemy import create_engine, select
from sqlalchemy.engine import Engine

from dashboard.data.view_models import OverviewStats, RecordPayload
from minemod_audit.database import records
from minemod_audit.models import Finding
from minemod_audit.reports import render_findings_markdown

SENSITIVE_KEYS = {"token", "api_key", "apikey", "authorization", "x-api-key", "secret", "password"}


@st.cache_resource(show_spinner=False)
def create_read_engine(database_path: Path) -> Engine | None:
    if not database_path.exists():
        return None
    sqlite_path = database_path.resolve().as_posix()
    return create_engine(f"sqlite:///file:{sqlite_path}?mode=ro&uri=true", future=True)


def load_records(database_path: Path, kind: str) -> list[RecordPayload]:
    return _load_records(database_path, kind, database_revision(database_path))


@st.cache_data(show_spinner=False)
def _load_records(
    database_path: Path,
    kind: str,
    revision: tuple[int, int],
) -> list[RecordPayload]:
    del revision
    engine = create_read_engine(database_path)
    if engine is None:
        return []
    statement = select(records.c.payload).where(records.c.kind == kind).order_by(records.c.key)
    with engine.connect() as connection:
        rows = connection.execute(statement).all()
    return [sanitize_payload(dict(row.payload)) for row in rows]


def database_revision(database_path: Path) -> tuple[int, int]:
    try:
        stat = database_path.stat()
    except FileNotFoundError:
        return (0, 0)
    return (stat.st_mtime_ns, stat.st_size)


def sanitize_payload(payload: Any) -> Any:
    if isinstance(payload, dict):
        sanitized: dict[str, Any] = {}
        for key, value in payload.items():
            normalized_key = key.lower().replace("-", "_")
            if normalized_key.endswith("_token_count"):
                sanitized[key] = sanitize_payload(value)
            elif any(secret in normalized_key for secret in SENSITIVE_KEYS):
                sanitized[key] = "<redacted>"
            else:
                sanitized[key] = sanitize_payload(value)
        return sanitized
    if isinstance(payload, list):
        return [sanitize_payload(item) for item in payload]
    return payload


def overview_stats(database_path: Path) -> OverviewStats:
    return _overview_stats(database_path, database_revision(database_path))


@st.cache_data(show_spinner=False)
def _overview_stats(database_path: Path, revision: tuple[int, int]) -> OverviewStats:
    del revision
    vulnerabilities = load_records(database_path, "vulnerabilities")
    findings = load_records(database_path, "findings")
    manual_review = [item for item in findings if item.get("requires_manual_review")]
    manual_review.extend(item for item in vulnerabilities if item.get("requires_manual_review"))
    runs = load_records(database_path, "runs")
    successful_runs = [run for run in runs if run.get("status") == "success"]
    last_success = max(
        (str(run.get("finished_at") or run.get("ended_at") or "") for run in successful_runs),
        default=None,
    )
    recent_fixes = load_records(database_path, "recent_fix_candidates")
    provider_status = {
        str(item.get("provider") or item.get("name") or "").lower(): str(
            item.get("status") or "unknown"
        )
        for item in load_records(database_path, "provider_status")
    }
    return OverviewStats(
        mods=len(load_records(database_path, "mods")),
        modpacks=len(load_records(database_path, "modpacks")),
        releases=len(load_records(database_path, "modpack_releases")),
        components=len(load_records(database_path, "modpack_components")),
        confirmed_vulnerabilities=sum(
            1 for item in vulnerabilities if item.get("status") == "confirmed"
        ),
        candidate_vulnerabilities=sum(
            1 for item in vulnerabilities if item.get("status") == "candidate"
        ),
        findings=len(findings),
        manual_review=len(manual_review),
        last_successful_run=last_success,
        recent_actionable_fixes=sum(
            1 for item in recent_fixes if item.get("status") == "actionable"
        ),
        legacy_exposures=len(findings),
        github_status=provider_status.get("github", "unknown"),
        modrinth_status=provider_status.get("modrinth", "unknown"),
        curseforge_status=provider_status.get("curseforge", "unknown"),
        database_size=_format_database_size(database_path),
    )


def counts_by(records_payload: list[RecordPayload], field: str) -> dict[str, int]:
    counter: Counter[str] = Counter()
    for item in records_payload:
        value = item.get(field)
        if isinstance(value, list):
            for element in value:
                counter[str(element or "unknown")] += 1
        else:
            counter[str(value or "unknown")] += 1
    return dict(counter)


def record_kind_counts(database_path: Path) -> dict[str, int]:
    engine = create_read_engine(database_path)
    if engine is None:
        return {}
    statement = select(records.c.kind)
    counter: Counter[str] = Counter()
    with engine.connect() as connection:
        for row in connection.execute(statement):
            counter[str(row.kind)] += 1
    return dict(counter)


def ai_usage_stats(database_path: Path) -> dict[str, int]:
    entries = load_records(database_path, "gemini_analysis_cache")
    candidates = load_records(database_path, "recent_security_fix_candidates")
    return {
        "cached_analyses": len(entries),
        "annotated_candidates": sum(1 for item in candidates if item.get("ai_verdict")),
        "cache_hits": sum(1 for item in candidates if item.get("ai_cache_hit")),
        "input_tokens": sum(int(item.get("input_token_count") or 0) for item in entries),
        "output_tokens": sum(int(item.get("output_token_count") or 0) for item in entries),
    }


AI_VERDICT_RANK = {
    "confirmed_public_vulnerability": 5,
    "probable_exploitable_bug": 4,
    "interesting_security_fix": 3,
    "normal_bugfix": 2,
    "insufficient_evidence": 1,
    "unrelated": 0,
}

ACTIONABLE_AI_VERDICTS = {
    "confirmed_public_vulnerability",
    "probable_exploitable_bug",
    "interesting_security_fix",
}

ACTIONABLE_CATEGORIES = {
    "confirmed_public_fix",
    "likely_security_fix",
    "interesting_bugfix",
}


def security_candidate_rows(database_path: Path) -> list[RecordPayload]:
    rows = load_records(database_path, "recent_security_fix_candidates")
    if not rows:
        rows = load_records(database_path, "recent_fix_candidates")
    enriched: list[RecordPayload] = []
    for row in rows:
        copy = dict(row)
        affected = copy.get("affected_modpacks") or []
        affected_list = affected if isinstance(affected, list) else []
        latest_affected = sum(
            1
            for item in affected_list
            if isinstance(item, dict) and item.get("latest_pack_release")
        )
        copy["affected_modpacks_count"] = len(affected_list)
        copy["latest_affected_modpacks"] = latest_affected
        copy["exposure_status"] = _exposure_status(copy, latest_affected, len(affected_list))
        copy["priority"] = security_candidate_priority(copy)
        copy["attention_level"] = _attention_level(copy)
        copy["attention_reason"] = _attention_reason(copy)
        copy["ai_label"] = _ai_label(copy)
        copy["fix_status"] = _fix_status(copy)
        copy["modpack_status"] = _modpack_status(copy)
        copy["risk_summary"] = _risk_summary(copy)
        copy["review_action"] = _review_action(copy)
        copy["dashboard_actionable"] = _dashboard_actionable(copy)
        copy["popularity_summary"] = _popularity_summary(copy)
        copy["evidence_links_count"] = sum(
            1
            for field in ("repository", "issue_url", "pull_request_url", "commit_url")
            if copy.get(field)
        )
        enriched.append(copy)
    return sorted(
        enriched,
        key=lambda item: (
            int(item.get("priority") or 0),
            int(item.get("ai_confidence") or 0),
            int(item.get("confidence") or 0),
            str(item.get("release_date") or ""),
        ),
        reverse=True,
    )


def crawler_events(database_path: Path, *, candidate_id: str | None = None) -> list[RecordPayload]:
    rows = load_records(database_path, "crawler_events")
    if candidate_id:
        rows = [row for row in rows if row.get("candidate_id") == candidate_id]
    return sorted(rows, key=lambda item: str(item.get("created_at") or ""), reverse=True)


def security_candidate_priority(row: RecordPayload) -> int:
    ai_rank = AI_VERDICT_RANK.get(str(row.get("ai_verdict") or ""), 0) * 100
    affected = int(row.get("affected_modpacks_count") or 0)
    latest_affected = int(row.get("latest_affected_modpacks") or 0)
    base = int(row.get("confidence") or 0)
    ai_confidence = int(row.get("ai_confidence") or 0)
    popularity_score = int(row.get("popularity_score") or 0)
    return ai_rank + ai_confidence + base + affected * 10 + latest_affected * 25 + popularity_score


def _attention_level(row: RecordPayload) -> str:
    ai_verdict = str(row.get("ai_verdict") or "")
    category = str(row.get("category") or "")
    latest_affected = int(row.get("latest_affected_modpacks") or 0)
    affected = int(row.get("affected_modpacks_count") or 0)
    confidence = int(row.get("confidence") or 0)
    ai_confidence = int(row.get("ai_confidence") or 0)
    if ai_verdict in {"confirmed_public_vulnerability", "probable_exploitable_bug"}:
        return "urgent"
    if ai_verdict in {"normal_bugfix", "unrelated"} and latest_affected == 0:
        return "low"
    if ai_verdict == "insufficient_evidence" and latest_affected == 0:
        return "manual" if affected else "low"
    if latest_affected > 0 and (ai_verdict in ACTIONABLE_AI_VERDICTS or confidence >= 60):
        return "high"
    if ai_verdict == "interesting_security_fix" or category in ACTIONABLE_CATEGORIES:
        return "review"
    if affected > 0 and (confidence >= 60 or ai_confidence >= 60):
        return "review"
    return "manual"


def _dashboard_actionable(row: RecordPayload) -> bool:
    ai_verdict = str(row.get("ai_verdict") or "")
    attention = str(row.get("attention_level") or "")
    affected = int(row.get("affected_modpacks_count") or 0)
    latest_affected = int(row.get("latest_affected_modpacks") or 0)
    if attention in {"urgent", "high"}:
        return True
    if ai_verdict in ACTIONABLE_AI_VERDICTS:
        return True
    return affected > 0 and (attention == "review" or latest_affected > 0)


def _attention_reason(row: RecordPayload) -> str:
    level = str(row.get("attention_level") or "")
    latest_affected = int(row.get("latest_affected_modpacks") or 0)
    affected = int(row.get("affected_modpacks_count") or 0)
    ai_verdict = str(row.get("ai_verdict") or "")
    if latest_affected:
        return f"{latest_affected} latest modpack release(s) still match the old version."
    if affected:
        return f"{affected} historical modpack release(s) use the old version."
    if ai_verdict in {"normal_bugfix", "unrelated"}:
        return "AI did not find enough security evidence."
    if level == "manual":
        return "Needs a human check because evidence is incomplete."
    return "Candidate has public fix evidence worth checking."


def _ai_label(row: RecordPayload) -> str:
    verdict = str(row.get("ai_verdict") or "")
    status = str(row.get("ai_status") or "")
    labels = {
        "confirmed_public_vulnerability": "AI: confirmed public vulnerability",
        "probable_exploitable_bug": "AI: probable exploitable bug",
        "interesting_security_fix": "AI: interesting security fix",
        "normal_bugfix": "AI: normal bug fix",
        "insufficient_evidence": "AI: insufficient evidence",
        "unrelated": "AI: unrelated",
        "valid": "AI: valid",
        "invalid": "AI: rejected response",
        "skipped": "AI: skipped",
    }
    if verdict:
        return labels.get(verdict, f"AI: {verdict}")
    if status:
        return labels.get(status, f"AI: {status}")
    return "AI: not analyzed"


def _fix_status(row: RecordPayload) -> str:
    old_version = str(row.get("old_version") or "?")
    fixed_version = str(row.get("fixed_version") or "")
    if fixed_version:
        return f"Fix identified: {old_version} -> {fixed_version}"
    return f"Old version known: {old_version}; fixed version missing"


def _modpack_status(row: RecordPayload) -> str:
    affected = int(row.get("affected_modpacks_count") or 0)
    latest_affected = int(row.get("latest_affected_modpacks") or 0)
    if affected == 0:
        return "No exact modpack match yet"
    if latest_affected > 0:
        return f"{latest_affected} latest release(s) still affected"
    return f"{affected} old release(s) affected, latest releases look patched or unknown"


def _risk_summary(row: RecordPayload) -> str:
    ai_summary = str(row.get("ai_concise_explanation") or "").strip()
    if ai_summary:
        return ai_summary
    impact = str(row.get("ai_potential_impact") or row.get("potential_impact") or "").strip()
    if impact:
        return impact
    patch_summary = str(row.get("patch_summary") or "").strip()
    if patch_summary:
        return patch_summary
    return "No concise explanation available yet."


def _popularity_summary(row: RecordPayload) -> str:
    downloads = int(row.get("mod_downloads") or 0)
    presence = int(row.get("modpack_presence_count") or 0)
    rank = row.get("popularity_rank")
    rank_part = f", rank #{rank}" if rank else ""
    return (
        f"{downloads:,} mod downloads{rank_part}; "
        f"{presence} indexed modpack release(s); "
        f"popularity score {int(row.get('popularity_score') or 0)}"
    )


def _review_action(row: RecordPayload) -> str:
    verdict = str(row.get("ai_verdict") or "")
    latest_affected = int(row.get("latest_affected_modpacks") or 0)
    affected = int(row.get("affected_modpacks_count") or 0)
    if verdict in {"confirmed_public_vulnerability", "probable_exploitable_bug"}:
        return "Check evidence and impacted latest modpacks first."
    if latest_affected > 0:
        return "Verify whether the pack maintainer has released a patched version."
    if verdict == "interesting_security_fix":
        return "Read the linked PR/commit before deciding if it is exploitable."
    if affected > 0:
        return "Historical exposure only; lower priority unless the pack release is still used."
    if verdict in {"normal_bugfix", "unrelated"}:
        return "Do not spend time unless new evidence appears."
    return "Manual review only if the mod is important to your target scope."


def _exposure_status(row: RecordPayload, latest_affected: int, affected_count: int) -> str:
    if affected_count == 0:
        return "no_modpack_match"
    if latest_affected > 0:
        return "latest_pack_still_affected"
    if row.get("fixed_version"):
        return "old_pack_release_only"
    return "manual_review"


def latest_log_summary(log_directory: Path) -> dict[str, str]:
    if not log_directory.exists():
        return {
            "name": "none",
            "status": "not_started",
            "last_line": "No logs directory found.",
            "updated_at": "",
        }
    logs = sorted(
        log_directory.glob("*crawl-*.out.log"),
        key=lambda item: item.stat().st_mtime,
        reverse=True,
    )
    if not logs:
        return {
            "name": "none",
            "status": "not_started",
            "last_line": "No crawler log found.",
            "updated_at": "",
        }
    latest = logs[0]
    lines = latest.read_text(encoding="utf-8", errors="replace").splitlines()
    non_empty = [line for line in lines if line.strip()]
    last_line = non_empty[-1] if non_empty else "Log is empty."
    status = "running"
    if any(line.startswith("EXIT") for line in non_empty):
        status = "complete" if any(line.endswith(" 0") for line in non_empty) else "failed"
    return {
        "name": latest.name,
        "status": status,
        "last_line": last_line,
        "updated_at": latest.stat().st_mtime_ns.__str__(),
    }


def filter_records(
    rows: list[RecordPayload],
    *,
    search: str = "",
    provider: str = "all",
    status: str = "all",
    loader: str = "all",
    minecraft_version: str = "all",
    has_vulnerability: bool | None = None,
    min_downloads: int = 0,
    manual_review_only: bool = False,
) -> list[RecordPayload]:
    search_lc = search.lower().strip()
    filtered: list[RecordPayload] = []
    for row in rows:
        searchable = " ".join(str(value) for value in row.values()).lower()
        if search_lc and search_lc not in searchable:
            continue
        if provider != "all" and str(row.get("provider") or "") != provider:
            continue
        if status != "all" and str(row.get("status") or "") != status:
            continue
        loaders = row.get("loaders") or row.get("loader") or row.get("categories")
        if loader != "all" and loader not in _as_strings(loaders):
            continue
        versions = (
            row.get("game_versions") or row.get("latest_versions") or row.get("minecraft_version")
        )
        if minecraft_version != "all" and minecraft_version not in _as_strings(versions):
            continue
        if has_vulnerability is True and int(row.get("vulnerability_count") or 0) <= 0:
            continue
        if int(row.get("download_count") or row.get("downloads") or 0) < min_downloads:
            continue
        if manual_review_only and not row.get("requires_manual_review"):
            continue
        filtered.append(row)
    return filtered


def enrich_mod_rows(database_path: Path, rows: list[RecordPayload]) -> list[RecordPayload]:
    vulnerabilities = load_records(database_path, "vulnerabilities")
    components = load_records(database_path, "modpack_components")
    prioritized = {
        str(item.get("project_id")): item
        for item in load_records(database_path, "prioritized_mods")
    }
    vulnerability_counts = counts_by(vulnerabilities, "mod_project_id")
    modpack_counts = counts_by(components, "mod_project_id")
    enriched: list[RecordPayload] = []
    for row in rows:
        project_id = str(row.get("project_id"))
        priority = prioritized.get(project_id, {})
        copy = dict(row)
        copy["loaders"] = row.get("loaders") or row.get("categories") or []
        copy["game_versions"] = row.get("game_versions") or row.get("latest_versions") or []
        copy["repository"] = row.get("repository") or row.get("source_url")
        copy["priority_score"] = priority.get("score", "")
        copy["vulnerability_count"] = vulnerability_counts.get(project_id, 0)
        copy["modpack_count"] = modpack_counts.get(project_id, 0)
        enriched.append(copy)
    return enriched


def enrich_modpack_rows(database_path: Path, rows: list[RecordPayload]) -> list[RecordPayload]:
    releases = load_records(database_path, "modpack_releases")
    components = load_records(database_path, "modpack_components")
    findings = load_records(database_path, "findings")
    release_counts = counts_by(releases, "modpack_project_id")
    component_counts: Counter[str] = Counter()
    release_to_pack = {
        str(release.get("file_id")): str(release.get("modpack_project_id"))
        for release in releases
        if release.get("file_id")
    }
    for component in components:
        pack_id = release_to_pack.get(str(component.get("modpack_file_id")))
        if pack_id:
            component_counts[pack_id] += 1
    finding_counts = counts_by(findings, "modpack_name")
    severity_by_pack: dict[str, str] = {}
    for finding in findings:
        pack = str(finding.get("modpack_name") or "")
        severity = str(finding.get("severity") or finding.get("impact_category") or "")
        if severity:
            severity_by_pack[pack] = severity
    enriched: list[RecordPayload] = []
    for row in rows:
        project_id = str(row.get("project_id"))
        copy = dict(row)
        related_releases = [
            release for release in releases if str(release.get("modpack_project_id")) == project_id
        ]
        copy["minecraft_versions"] = _unique_values(
            release.get("minecraft_version") for release in related_releases
        )
        copy["loaders"] = _unique_values(release.get("loader") for release in related_releases)
        copy["release_count"] = release_counts.get(project_id, 0)
        copy["component_count"] = component_counts.get(project_id, 0)
        copy["finding_count"] = finding_counts.get(str(row.get("name") or ""), 0)
        copy["highest_severity"] = severity_by_pack.get(str(row.get("name") or ""), "")
        enriched.append(copy)
    return enriched


def normalize_finding_rows(rows: list[RecordPayload]) -> list[RecordPayload]:
    normalized: list[RecordPayload] = []
    for row in rows:
        copy = dict(row)
        source_urls = row.get("source_urls")
        if isinstance(source_urls, list) and source_urls:
            copy["source_url"] = source_urls[0]
        normalized.append(copy)
    return normalized


def paginate(rows: list[RecordPayload], *, page: int, page_size: int) -> list[RecordPayload]:
    safe_page = max(1, page)
    safe_size = max(1, page_size)
    start = (safe_page - 1) * safe_size
    return rows[start : start + safe_size]


def export_csv(rows: list[RecordPayload]) -> str:
    if not rows:
        return ""
    output = io.StringIO()
    fieldnames = sorted({key for row in rows for key in row})
    writer = csv.DictWriter(output, fieldnames=fieldnames)
    writer.writeheader()
    for row in rows:
        writer.writerow({key: _stringify(row.get(key)) for key in fieldnames})
    return output.getvalue()


def export_json(rows: list[RecordPayload]) -> str:
    return json.dumps(rows, indent=2, ensure_ascii=False)


def export_findings_markdown(rows: list[RecordPayload]) -> str:
    findings = [Finding.model_validate(row) for row in rows]
    return render_findings_markdown(findings)


def status_options(rows: list[RecordPayload]) -> list[str]:
    return ["all", *sorted({str(row.get("status")) for row in rows if row.get("status")})]


def provider_options(rows: list[RecordPayload]) -> list[str]:
    return ["all", *sorted({str(row.get("provider")) for row in rows if row.get("provider")})]


def loader_options(rows: list[RecordPayload]) -> list[str]:
    values = {
        item
        for row in rows
        for item in _as_strings(row.get("loaders") or row.get("loader") or row.get("categories"))
    }
    return ["all", *sorted(values)]


def minecraft_version_options(rows: list[RecordPayload]) -> list[str]:
    values = {
        item
        for row in rows
        for item in _as_strings(
            row.get("game_versions")
            or row.get("latest_versions")
            or row.get("minecraft_versions")
            or row.get("minecraft_version")
        )
    }
    return ["all", *sorted(values)]


def _as_strings(value: Any) -> list[str]:
    if value is None:
        return []
    if isinstance(value, list):
        return [str(item) for item in value if item is not None]
    return [str(value)]


def _stringify(value: Any) -> str:
    if isinstance(value, (dict, list)):
        return json.dumps(value, ensure_ascii=False)
    return "" if value is None else str(value)


def _unique_values(values: Iterable[object]) -> list[str]:
    seen: set[str] = set()
    unique: list[str] = []
    for value in values:
        if value is None:
            continue
        text = str(value)
        if text not in seen:
            seen.add(text)
            unique.append(text)
    return unique


def _format_database_size(database_path: Path) -> str:
    if not database_path.exists():
        return "0 B"
    size = database_path.stat().st_size
    if size >= 1024 * 1024:
        return f"{size / (1024 * 1024):.1f} MB"
    if size >= 1024:
        return f"{size / 1024:.1f} kB"
    return str(f"{size} B")
