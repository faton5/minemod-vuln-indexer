from minemod_audit.models import Finding
from minemod_audit.reports import render_findings_markdown


def test_markdown_report_includes_manual_review_reason() -> None:
    finding = Finding(
        mod_name="ExampleMod",
        mod_version="1.2.3",
        modpack_name="Example Pack",
        modpack_release="4.0",
        minecraft_version="1.12.2",
        loader="Forge",
        affected_range="<1.2.5",
        fixed_versions=["1.2.5"],
        impact_category="item_duplication",
        confidence=90,
        status="confirmed",
        source_urls=["https://example.invalid/advisory"],
        requires_manual_review=True,
        manual_review_reason="version comparison is not reliable",
    )

    markdown = render_findings_markdown([finding])

    assert "[CONFIRMED] ExampleMod 1.2.3" in markdown
    assert "Test actif effectue : non" in markdown
    assert "Revue manuelle : version comparison is not reliable" in markdown
