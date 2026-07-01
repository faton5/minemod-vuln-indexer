from dataclasses import dataclass
from typing import Any

RecordPayload = dict[str, Any]


@dataclass(frozen=True)
class OverviewStats:
    mods: int
    modpacks: int
    releases: int
    components: int
    confirmed_vulnerabilities: int
    candidate_vulnerabilities: int
    findings: int
    manual_review: int
    last_successful_run: str | None
    recent_actionable_fixes: int = 0
    legacy_exposures: int = 0
    github_status: str = "unknown"
    modrinth_status: str = "unknown"
    curseforge_status: str = "unknown"
    database_size: str = "0 B"
