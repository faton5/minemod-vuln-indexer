from datetime import UTC, datetime

from minemod_audit.models import Modpack, ModpackComponent, ModpackRelease, ModProject
from minemod_audit.release_lag import (
    build_canonical_mods,
    classify_release_diff,
    correlate_release_lag,
    rank_libraries_by_modpack_releases,
)


def test_canonical_mod_prefers_normalized_github_repository_identity() -> None:
    curseforge_component = ModpackComponent(
        modpack_file_id="curseforge:pack-file-a",
        mod_project_id="curseforge:404465",
        mod_file_id="curseforge:5001",
        provider="curseforge",
        provider_project_id="404465",
        mod_name="FTB Library",
        mod_version="2101.1.14",
        source_url="https://github.com/FTBTeam/FTB-Library",
        resolution_status="resolved",
        requires_manual_review=False,
    )
    modrinth_project = ModProject(
        project_id="modrinth:ftb-library",
        provider="modrinth",
        provider_project_id="ftb-library",
        name="FTB Library",
        slug="ftb-library",
        source_url="https://github.com/ftbteam/ftb-library/",
    )

    canonicals = build_canonical_mods(
        mods=[modrinth_project],
        components=[curseforge_component],
    )

    assert len(canonicals) == 1
    canonical = canonicals[0]
    assert canonical.canonical_id == "github:ftbteam/ftb-library"
    assert canonical.github_repository == "ftbteam/ftb-library"
    assert canonical.curseforge_project_ids == ["404465"]
    assert canonical.modrinth_project_ids == ["ftb-library"]
    assert set(canonical.aliases) == {"FTB Library", "ftb-library"}


def test_rank_libraries_uses_modpack_release_presence_not_downloads() -> None:
    high_download_low_presence = ModpackComponent(
        modpack_file_id="pack-a",
        mod_project_id="curseforge:popular-downloads",
        mod_file_id="file-a",
        mod_name="Popular Downloads",
        mod_version="1.0.0",
        resolution_status="resolved",
        requires_manual_review=False,
    )
    lower_download_high_presence = [
        ModpackComponent(
            modpack_file_id=f"pack-{index}",
            mod_project_id="curseforge:widely-used-library",
            mod_file_id=f"file-{index}",
            mod_name="Widely Used Library",
            mod_version="1.0.0",
            resolution_status="resolved",
            requires_manual_review=False,
        )
        for index in range(3)
    ]

    ranked = rank_libraries_by_modpack_releases(
        components=[high_download_low_presence, *lower_download_high_presence],
        canonicals=build_canonical_mods(
            mods=[],
            components=[high_download_low_presence, *lower_download_high_presence],
        ),
    )

    assert ranked[0].canonical_mod_id == "provider:curseforge:widely-used-library"
    assert ranked[0].modpack_release_count == 3


def test_ftb_library_nbt_fix_diff_is_detected_without_security_commit_message() -> None:
    patch = """@@ public void handle(ClientResponse response) {
+ if (currentlyEditing == null) {
+     LOGGER.warn("Rejecting unsolicited NBT edit response from client");
+     return;
+ }
+ if (!currentlyEditing.requestId().equals(response.requestId())) {
+     LOGGER.warn("Rejecting NBT edit response that does not match server request");
+     return;
+ }
+ CompoundTag sanitized = currentlyEditing.rebuildServerSide(response.payload());
  applyEdit(response.payload());
}"""

    candidate = classify_release_diff(
        canonical_mod_id="github:ftbteam/ftb-library",
        old_version="2101.1.14",
        new_version="2101.1.15",
        old_tag="v2101.1.14",
        new_tag="v2101.1.15",
        changed_files=["src/main/java/dev/ftb/mods/ftblibrary/nbt/EditNBTMessage.java"],
        patches=[patch],
        commit_message="Update library internals",
        published_at="2026-06-20T12:00:00Z",
        minecraft_branch="1.21",
        loader="neoforge",
        fixed_commit="abc123",
    )

    assert candidate.category == "client_state_validation"
    assert candidate.confidence >= 80
    assert "currentlyEditing" in candidate.explanation
    assert "server request" in candidate.explanation
    assert "unsolicited" in candidate.explanation
    assert candidate.relevant_patch_sections == [patch]


def test_release_lag_correlation_finds_modpack_still_on_previous_release() -> None:
    canonical = build_canonical_mods(
        mods=[],
        components=[
            ModpackComponent(
                modpack_file_id="curseforge:atm10-latest",
                mod_project_id="curseforge:404465",
                mod_file_id="curseforge:old-file",
                provider="curseforge",
                provider_project_id="404465",
                mod_name="FTB Library",
                mod_version="2101.1.14",
                source_url="https://github.com/FTBTeam/FTB-Library",
                resolution_status="resolved",
                requires_manual_review=False,
                loaders=["neoforge"],
                minecraft_versions=["1.21"],
            ),
            ModpackComponent(
                modpack_file_id="curseforge:other-pack",
                mod_project_id="curseforge:404465",
                mod_file_id="curseforge:new-file",
                provider="curseforge",
                provider_project_id="404465",
                mod_name="FTB Library",
                mod_version="2101.1.15",
                source_url="https://github.com/FTBTeam/FTB-Library",
                resolution_status="resolved",
                requires_manual_review=False,
                loaders=["neoforge"],
                minecraft_versions=["1.21"],
            ),
        ],
    )[0]
    candidate = classify_release_diff(
        canonical_mod_id=canonical.canonical_id,
        old_version="2101.1.14",
        new_version="2101.1.15",
        old_tag="v2101.1.14",
        new_tag="v2101.1.15",
        changed_files=["NBTEditHandler.java"],
        patches=[
            "+ if (currentlyEditing == null) return;\n"
            "+ if (!request.id().equals(response.id())) return;"
        ],
        commit_message="Refactor",
        published_at="2026-06-20T00:00:00Z",
        minecraft_branch="1.21",
        loader="neoforge",
        fixed_commit="abc123",
    )

    findings = correlate_release_lag(
        candidates=[candidate],
        canonicals=[canonical],
        components=[
            ModpackComponent(
                modpack_file_id="curseforge:atm10-latest",
                mod_project_id="curseforge:404465",
                mod_file_id="curseforge:old-file",
                provider="curseforge",
                provider_project_id="404465",
                mod_name="FTB Library",
                mod_version="2101.1.14",
                source_url="https://github.com/FTBTeam/FTB-Library",
                resolution_status="resolved",
                requires_manual_review=False,
                loaders=["neoforge"],
                minecraft_versions=["1.21"],
            ),
            ModpackComponent(
                modpack_file_id="curseforge:other-pack",
                mod_project_id="curseforge:404465",
                mod_file_id="curseforge:new-file",
                provider="curseforge",
                provider_project_id="404465",
                mod_name="FTB Library",
                mod_version="2101.1.15",
                source_url="https://github.com/FTBTeam/FTB-Library",
                resolution_status="resolved",
                requires_manual_review=False,
                loaders=["neoforge"],
                minecraft_versions=["1.21"],
            ),
        ],
        modpacks=[
            Modpack(
                project_id="curseforge:atm10",
                provider="curseforge",
                provider_project_id="atm10",
                name="All the Mods 10",
                slug="atm10",
            ),
            Modpack(
                project_id="curseforge:other",
                provider="curseforge",
                provider_project_id="other",
                name="Other Pack",
                slug="other",
            ),
        ],
        releases=[
            ModpackRelease(
                file_id="curseforge:atm10-latest",
                modpack_project_id="curseforge:atm10",
                display_name="latest",
                release_date="2026-07-01T00:00:00Z",
                minecraft_version="1.21",
                loader="neoforge",
            ),
            ModpackRelease(
                file_id="curseforge:other-pack",
                modpack_project_id="curseforge:other",
                display_name="latest",
                release_date="2026-07-01T00:00:00Z",
                minecraft_version="1.21",
                loader="neoforge",
            ),
        ],
        now=datetime(2026, 7, 2, tzinfo=UTC),
    )

    assert len(findings) == 1
    assert findings[0].status == "confirmed_lag"
    assert findings[0].modpack_name == "All the Mods 10"
    assert findings[0].old_version == "2101.1.14"
    assert findings[0].new_version == "2101.1.15"
    assert findings[0].days_since_fix == 12
    assert findings[0].latest_pack_release is True
