from datetime import UTC, datetime

from minemod_audit.models import Modpack, ModpackComponent, ModpackRelease
from minemod_audit.recent_security_fixes import (
    RecentFixRelease,
    classify_recent_fix,
    correlate_affected_modpacks,
    public_exploit_information_level,
)


def test_ftb_library_changelog_fix_is_detected_without_exploit_word() -> None:
    release = RecentFixRelease(
        mod_project_id="curseforge:404465",
        mod_name="FTB Library",
        repository="FTBTeam/FTB-Library",
        old_file_id="curseforge:6819021",
        new_file_id="curseforge:6819022",
        old_version="2101.1.31",
        fixed_version="2101.1.32",
        minecraft_version="1.21",
        loader="neoforge",
        release_date="2026-06-20T00:00:00Z",
        changelog=(
            "Fixed EditNBTResponsePacket accepting a client NBT edit response that "
            "did not match a server-side currentlyEditing request."
        ),
        changed_files=["src/main/java/dev/ftb/mods/ftblibrary/net/EditNBTResponsePacket.java"],
        patches=[
            "+ if (currentlyEditing == null) return;\n"
            "+ if (!currentlyEditing.requestId().equals(response.requestId())) return;"
        ],
    )

    candidate = classify_recent_fix(release, modpack_presence_count=5)

    assert candidate.category == "confirmed_public_fix"
    assert candidate.confidence >= 70
    assert candidate.old_version == "2101.1.31"
    assert candidate.fixed_version == "2101.1.32"
    assert candidate.public_exploit_information == "technical_description"
    assert "EditNBTResponsePacket" in candidate.patch_summary
    assert "server-side" in candidate.potential_impact


def test_public_exploit_information_levels_do_not_store_payloads() -> None:
    assert public_exploit_information_level("Fixed a dupe bug.") == "impact_only"
    assert (
        public_exploit_information_level("Steps to reproduce are listed in issue #12.")
        == "public_reproduction_steps"
    )
    assert public_exploit_information_level("Public PoC exists in linked report.") == "public_poc"


def test_correlate_affected_modpacks_uses_exact_old_file_or_version() -> None:
    release = RecentFixRelease(
        mod_project_id="curseforge:404465",
        mod_name="FTB Library",
        old_file_id="curseforge:6819021",
        new_file_id="curseforge:6819022",
        old_version="2101.1.31",
        fixed_version="2101.1.32",
        minecraft_version="1.21",
        loader="neoforge",
        release_date="2026-06-20T00:00:00Z",
        changelog="NBT fix",
        changed_files=[],
        patches=[],
    )
    candidate = classify_recent_fix(release, modpack_presence_count=5)

    affected = correlate_affected_modpacks(
        candidate=candidate,
        components=[
            ModpackComponent(
                modpack_file_id="curseforge:atm10-latest",
                mod_project_id="curseforge:404465",
                mod_file_id="curseforge:6819021",
                provider="curseforge",
                provider_project_id="404465",
                provider_version_id="6819021",
                mod_name="FTB Library",
                mod_version="2101.1.31",
                resolution_status="resolved",
                requires_manual_review=False,
                minecraft_versions=["1.21"],
                loaders=["neoforge"],
            ),
            ModpackComponent(
                modpack_file_id="curseforge:old-pack-release",
                mod_project_id="curseforge:404465",
                mod_file_id="curseforge:6819021",
                provider="curseforge",
                provider_project_id="404465",
                provider_version_id="6819021",
                mod_name="FTB Library",
                mod_version="2101.1.31",
                resolution_status="resolved",
                requires_manual_review=False,
                minecraft_versions=["1.21"],
                loaders=["neoforge"],
            ),
        ],
        modpacks=[
            Modpack(
                project_id="curseforge:atm10",
                provider="curseforge",
                provider_project_id="atm10",
                name="All the Mods 10",
                slug="atm10",
                download_count=1000000,
            )
        ],
        releases=[
            ModpackRelease(
                file_id="curseforge:atm10-latest",
                modpack_project_id="curseforge:atm10",
                display_name="ATM10 4.0",
                release_date="2026-07-01T00:00:00Z",
                minecraft_version="1.21",
                loader="neoforge",
            ),
            ModpackRelease(
                file_id="curseforge:old-pack-release",
                modpack_project_id="curseforge:atm10",
                display_name="ATM10 3.9",
                release_date="2026-06-01T00:00:00Z",
                minecraft_version="1.21",
                loader="neoforge",
            ),
        ],
        now=datetime(2026, 7, 2, tzinfo=UTC),
    )

    assert len(affected) == 2
    latest = next(item for item in affected if item.modpack_release == "ATM10 4.0")
    old = next(item for item in affected if item.modpack_release == "ATM10 3.9")
    assert latest.latest_pack_release is True
    assert old.latest_pack_release is False
    assert latest.same_minecraft_loader is True
    assert latest.days_since_fix == 12
