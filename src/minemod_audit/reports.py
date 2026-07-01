import csv
import json
from collections.abc import Sequence
from pathlib import Path
from typing import Any

from pydantic import BaseModel

from minemod_audit.models import Finding


def _dump_model(item: BaseModel) -> dict[str, Any]:
    return item.model_dump(mode="json")


def render_findings_markdown(findings: list[Finding]) -> str:
    if not findings:
        return "# Findings\n\nAucun finding produit.\n"

    lines = ["# Findings", ""]
    for finding in findings:
        lines.extend(
            [
                f"[{finding.status.upper()}] {finding.mod_name} {finding.mod_version}",
                "",
                f"Modpack : {finding.modpack_name} {finding.modpack_release}",
                f"Minecraft : {finding.minecraft_version or 'unknown'}",
                f"Loader : {finding.loader or 'unknown'}",
                f"Version detectee : {finding.mod_version}",
                f"Plage affectee : {finding.affected_range or 'unknown'}",
                f"Premiere version corrigee : {', '.join(finding.fixed_versions) or 'unknown'}",
                f"Impact : {finding.impact_category}",
                f"Confiance : {finding.confidence}/100",
                "Test actif effectue : non",
            ]
        )
        if finding.source_urls:
            lines.append(f"Sources : {', '.join(finding.source_urls)}")
        if finding.requires_manual_review:
            reason = finding.manual_review_reason or "validation manuelle requise"
            lines.append(f"Revue manuelle : {reason}")
        lines.append("")
    return "\n".join(lines)


def write_json(path: Path, items: Sequence[BaseModel] | Sequence[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = [_dump_model(item) if isinstance(item, BaseModel) else item for item in items]
    path.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")


def write_csv(path: Path, rows: list[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fieldnames = sorted({key for row in rows for key in row})
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)


def write_reports(
    output_directory: Path,
    *,
    mods: list[BaseModel],
    repositories: list[BaseModel],
    vulnerabilities: list[BaseModel],
    components: list[BaseModel],
    findings: list[Finding],
) -> None:
    output_directory.mkdir(parents=True, exist_ok=True)
    write_json(output_directory / "mods.json", mods)
    write_json(output_directory / "repositories.json", repositories)
    write_json(output_directory / "vulnerabilities.json", vulnerabilities)
    write_json(output_directory / "findings.json", findings)
    write_csv(
        output_directory / "modpack_components.csv",
        [_dump_model(item) for item in components],
    )
    write_csv(
        output_directory / "manual_review.csv",
        [_dump_model(item) for item in findings if item.requires_manual_review],
    )
    unresolved = [
        _dump_model(item)
        for item in repositories
        if getattr(item, "repository", None) is None or getattr(item, "status", "") != "resolved"
    ]
    write_csv(output_directory / "unresolved_repositories.csv", unresolved)
    (output_directory / "findings.md").write_text(
        render_findings_markdown(findings),
        encoding="utf-8",
    )
