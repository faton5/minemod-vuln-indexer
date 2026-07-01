import pytest

from minemod_audit.lab.validation import (
    ValidationScopeError,
    ValidationTarget,
    build_validation_plan,
)


def test_validation_target_accepts_localhost_lab() -> None:
    target = ValidationTarget(host="127.0.0.1", port=25565, purpose="local forge lab")

    plan = build_validation_plan(target, mod_id="example-mod", version="1.2.3")

    assert target.is_local is True
    assert plan.mode == "local_validation"
    assert plan.mod_id == "example-mod"
    assert "non-exploit" in plan.safety_controls


def test_validation_target_rejects_public_server_targeting() -> None:
    with pytest.raises(ValidationScopeError, match="public server targeting"):
        ValidationTarget(host="play.example.org", port=25565, purpose="notify admins")
