from datetime import UTC, datetime, timedelta

from minemod_audit.models import SecurityEvidenceBundle
from minemod_audit.security_discovery import (
    patch_adds_server_validation,
    score_security_bundle,
    since_for_lookback,
    visible_recent_fix_bundles,
)

NOW = datetime(2026, 7, 1, tzinfo=UTC)
SINCE = since_for_lookback(180, now=NOW)


def test_three_year_old_issue_without_activity_stays_weak_signal() -> None:
    bundle = SecurityEvidenceBundle(
        mod_project_id="modrinth:old",
        mod_name="Old Mod",
        repository="example/old",
        issue_url="https://github.com/example/old/issues/1",
        updated_at=(NOW - timedelta(days=1095)).isoformat(),
        matched_terms=["security fix"],
    )

    scored = score_security_bundle(bundle, lookback_since=SINCE)

    assert scored.status == "weak_signal"
    assert scored.confidence == 0
    assert any("stale issue" in reason for reason in scored.reasons)


def test_dupe_issue_without_other_evidence_stays_weak_signal() -> None:
    bundle = SecurityEvidenceBundle(
        mod_project_id="modrinth:dupe",
        mod_name="Dupe Mod",
        repository="example/dupe",
        issue_url="https://github.com/example/dupe/issues/2",
        updated_at=NOW.isoformat(),
        matched_terms=["dupe"],
    )

    scored = score_security_bundle(bundle, lookback_since=SINCE, modpack_count=10)

    assert scored.status == "weak_signal"
    assert scored.confidence <= 30


def test_merged_pr_with_commit_and_release_scores_high() -> None:
    bundle = SecurityEvidenceBundle(
        mod_project_id="modrinth:fix",
        mod_name="Fix Mod",
        repository="example/fix",
        pull_request_url="https://github.com/example/fix/pull/10",
        pull_request_merged_at=NOW.isoformat(),
        commit_sha="abc123",
        commit_url="https://github.com/example/fix/commit/abc123",
        release_url="https://github.com/example/fix/releases/tag/1.2.4",
        release_version="1.2.4",
        fixed_versions=["1.2.4"],
        matched_terms=["server-side validation", "fix dupe"],
        changed_files=["src/main/java/PacketHandler.java"],
        patch_summary=(
            "Changed files: PacketHandler.java. "
            "Validation-related additions: permission, packet, server-side"
        ),
    )

    scored = score_security_bundle(bundle, lookback_since=SINCE, modpack_count=5)

    assert scored.status == "actionable"
    assert scored.confidence >= 70


def test_invalid_or_duplicate_issue_is_rejected() -> None:
    bundle = SecurityEvidenceBundle(
        mod_project_id="modrinth:invalid",
        mod_name="Invalid Mod",
        repository="example/invalid",
        issue_url="https://github.com/example/invalid/issues/3",
        updated_at=NOW.isoformat(),
        matched_terms=["security fix"],
        reasons=["duplicate"],
    )

    scored = score_security_bundle(bundle, lookback_since=SINCE)

    assert scored.status == "rejected"


def test_patch_validation_detection_requires_added_validation_terms() -> None:
    assert patch_adds_server_validation(["+ if (!player.hasPermission(node)) return;"])
    assert not patch_adds_server_validation(["+ renderTooltip(matrixStack);"])


def test_dashboard_visibility_hides_weak_signals_by_default() -> None:
    actionable = SecurityEvidenceBundle(
        mod_project_id="modrinth:a",
        mod_name="A",
        repository="example/a",
        status="actionable",
    )
    weak = SecurityEvidenceBundle(
        mod_project_id="modrinth:w",
        mod_name="W",
        repository="example/w",
        status="weak_signal",
    )

    assert visible_recent_fix_bundles([actionable, weak]) == [actionable]
    assert visible_recent_fix_bundles([actionable, weak], include_weak=True) == [actionable, weak]
