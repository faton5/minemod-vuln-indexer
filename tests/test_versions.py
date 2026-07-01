from minemod_audit.versioning import VersionDecision, is_version_affected


def test_semver_like_version_inside_affected_range() -> None:
    decision = is_version_affected("1.2.3", affected="<1.2.5", fixed="1.2.5")

    assert decision == VersionDecision.AFFECTED


def test_exact_fixed_version_is_not_affected() -> None:
    decision = is_version_affected("0.5.78", affected="<0.5.78", fixed="0.5.78")

    assert decision == VersionDecision.NOT_AFFECTED


def test_non_comparable_version_requires_manual_review() -> None:
    decision = is_version_affected("forge-build-latest", affected="<1.0.0", fixed="1.0.0")

    assert decision == VersionDecision.MANUAL_REVIEW
