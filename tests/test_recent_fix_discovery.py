from datetime import UTC, datetime, timedelta
from typing import cast

from minemod_audit.advisories import GitHubClient
from minemod_audit.models import PrioritizedMod, SecurityEvidenceBundle
from minemod_audit.pipeline import (
    _bundles_from_advisories,
    _bundles_from_pull_requests,
    _vulnerability_from_bundle,
)
from minemod_audit.security_discovery import (
    detect_matched_terms,
    patch_adds_server_validation,
    score_security_bundle,
    since_for_lookback,
    visible_recent_fix_bundles,
)

NOW = datetime(2026, 7, 1, tzinfo=UTC)
SINCE = since_for_lookback(180, now=NOW)


class FakePullRequestGitHub:
    def get_pull_request(self, repository: str, pull_number: int) -> dict[str, object]:
        assert repository == "example/fix"
        assert pull_number == 42
        return {
            "html_url": "https://github.com/example/fix/pull/42",
            "merged_at": NOW.isoformat(),
            "merge_commit_sha": "merge123",
            "author_association": "MEMBER",
            "title": "Fix item duplication",
            "body": "Reject invalid slot packets.",
        }

    def list_pull_request_commits(
        self,
        repository: str,
        pull_number: int,
    ) -> list[dict[str, object]]:
        assert repository == "example/fix"
        assert pull_number == 42
        return [{"sha": "prep123"}, {"sha": "fix123"}]

    def get_commit_details(self, repository: str, sha: str) -> dict[str, object]:
        assert repository == "example/fix"
        patches = {
            "merge123": "+ validatePacket(packet);\n+ checkPlayerDistance(player);",
            "prep123": "+ cleanupFormatting();",
            "fix123": "+ rejectInvalidSlot(slot);\n+ verifySenderPermissions(sender);",
        }
        return {
            "sha": sha,
            "html_url": f"https://github.com/example/fix/commit/{sha}",
            "files": [
                {
                    "filename": f"src/{sha}.java",
                    "patch": patches[sha],
                }
            ],
        }


def _prioritized_mod() -> PrioritizedMod:
    return PrioritizedMod(
        project_id="modrinth:fix",
        provider="modrinth",
        provider_project_id="fix",
        name="Fix Mod",
        slug="fix-mod",
        download_count=1000,
        dependency_count=2,
        modpack_count=2,
        score=1000,
        repository="example/fix",
    )


def test_github_advisory_versions_are_read_from_vulnerabilities() -> None:
    bundles = _bundles_from_advisories(
        _prioritized_mod(),
        "example/fix",
        [
            {
                "html_url": "https://github.com/advisories/GHSA-test",
                "summary": "Security fix",
                "published_at": NOW.isoformat(),
                "updated_at": NOW.isoformat(),
                "vulnerabilities": [
                    {
                        "first_patched_version": "1.2.4",
                        "vulnerable_version_range": "<1.2.4",
                    }
                ],
            }
        ],
        lookback_since=SINCE,
    )

    assert bundles[0].fixed_versions == ["1.2.4"]
    assert bundles[0].affected_versions == ["<1.2.4"]


def test_generic_release_term_does_not_create_fixed_version() -> None:
    bundles = _bundles_from_pull_requests(
        _prioritized_mod(),
        "example/fix",
        [
            {
                "html_url": "https://github.com/example/fix/pull/42",
                "title": "Security fix",
                "body": "Fix item duplication.",
                "matched_terms": ["security fix"],
            }
        ],
        github=cast(GitHubClient, FakePullRequestGitHub()),
        releases=[
            {
                "html_url": "https://github.com/example/fix/releases/tag/9.9.9",
                "tag_name": "9.9.9",
                "body": "Security fix for an unrelated bug.",
            }
        ],
    )

    assert bundles[0].release_url is None
    assert bundles[0].fixed_versions == []


def test_release_references_pr_before_fixed_version_is_accepted() -> None:
    bundles = _bundles_from_pull_requests(
        _prioritized_mod(),
        "example/fix",
        [
            {
                "html_url": "https://github.com/example/fix/pull/42",
                "title": "Security fix",
                "body": "Fix item duplication.",
                "matched_terms": ["security fix"],
            }
        ],
        github=cast(GitHubClient, FakePullRequestGitHub()),
        releases=[
            {
                "html_url": "https://github.com/example/fix/releases/tag/1.2.4",
                "tag_name": "1.2.4",
                "body": "Includes security fix from #42.",
            }
        ],
    )

    assert bundles[0].commit_sha == "merge123"
    assert bundles[0].pull_request_merged_at == NOW.isoformat()
    assert bundles[0].release_version == "1.2.4"
    assert bundles[0].fixed_versions == ["1.2.4"]
    assert any("fix123.java" in changed_file for changed_file in bundles[0].changed_files)


def test_recent_fix_terms_include_common_variants() -> None:
    text = (
        "Prevent duping by rejecting invalid slot packets, verifying sender permissions, "
        "and ignoring client supplied amount for item duplication."
    )

    assert detect_matched_terms(text) == [
        "client supplied amount",
        "duping",
        "invalid slot",
        "item duplication",
        "prevent duping",
        "sender permissions",
    ]


def test_vulnerability_preserves_recent_fix_status() -> None:
    bundle = SecurityEvidenceBundle(
        mod_project_id="modrinth:fix",
        mod_name="Fix Mod",
        repository="example/fix",
        pull_request_url="https://github.com/example/fix/pull/42",
        status="actionable",
    )

    vulnerability = _vulnerability_from_bundle(bundle)

    assert vulnerability.status == "actionable"


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
