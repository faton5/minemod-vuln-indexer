from pathlib import Path

from minemod_audit.config import Settings
from minemod_audit.models import (
    CanonicalMod,
    Modpack,
    ModpackComponent,
    ModpackRelease,
    ReleaseDiffCandidate,
    ReleaseLagFinding,
    ReleaseLagLibrary,
)
from minemod_audit.pipeline import Pipeline


def test_pipeline_builds_and_stores_canonical_mods(tmp_path: Path) -> None:
    pipeline = Pipeline(Settings(database=tmp_path / "test.db"))
    pipeline.store.replace_models(
        "modpack_components",
        [
            ModpackComponent(
                modpack_file_id="curseforge:pack-file",
                mod_project_id="curseforge:404465",
                mod_file_id="curseforge:old-file",
                provider="curseforge",
                provider_project_id="404465",
                mod_name="FTB Library",
                mod_version="2101.1.14",
                source_url="https://github.com/FTBTeam/FTB-Library",
                resolution_status="resolved",
                requires_manual_review=False,
            )
        ],
        key=lambda item: f"{item.modpack_file_id}:{item.mod_project_id}:{item.mod_file_id}",
    )

    canonicals = pipeline.build_canonical_mods()

    stored = pipeline.store.load_models("canonical_mods", CanonicalMod)
    assert canonicals == stored
    assert stored[0].canonical_id == "github:ftbteam/ftb-library"


def test_pipeline_hunts_release_lag_from_stored_candidates(tmp_path: Path) -> None:
    pipeline = Pipeline(Settings(database=tmp_path / "test.db"))
    canonical = CanonicalMod(
        canonical_id="github:ftbteam/ftb-library",
        github_repository="ftbteam/ftb-library",
        curseforge_project_ids=["404465"],
        aliases=["FTB Library"],
        loaders=["neoforge"],
        minecraft_branches=["1.21"],
    )
    pipeline.store.replace_models("canonical_mods", [canonical], key=lambda item: item.canonical_id)
    pipeline.store.replace_models(
        "release_diff_candidates",
        [
            ReleaseDiffCandidate(
                canonical_mod_id=canonical.canonical_id,
                old_version="2101.1.14",
                new_version="2101.1.15",
                old_tag="v2101.1.14",
                new_tag="v2101.1.15",
                changed_files=["NBTEditHandler.java"],
                relevant_patch_sections=["+ if (currentlyEditing == null) return;"],
                category="client_state_validation",
                explanation="currentlyEditing session state",
                confidence=90,
                fixed_commit="abc123",
                published_at="2026-06-20T00:00:00Z",
                minecraft_branch="1.21",
                loader="neoforge",
            )
        ],
        key=lambda item: f"{item.canonical_mod_id}:{item.old_version}:{item.new_version}",
    )
    pipeline.store.replace_models(
        "modpacks",
        [
            Modpack(
                project_id="curseforge:atm10",
                provider="curseforge",
                provider_project_id="atm10",
                name="All the Mods 10",
                slug="atm10",
            )
        ],
        key=lambda item: str(item.project_id),
    )
    pipeline.store.replace_models(
        "modpack_releases",
        [
            ModpackRelease(
                file_id="curseforge:atm10-latest",
                modpack_project_id="curseforge:atm10",
                display_name="latest",
                release_date="2026-07-01T00:00:00Z",
                minecraft_version="1.21",
                loader="neoforge",
            )
        ],
        key=lambda item: str(item.file_id),
    )
    pipeline.store.replace_models(
        "modpack_components",
        [
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
        key=lambda item: f"{item.modpack_file_id}:{item.mod_project_id}:{item.mod_file_id}",
    )

    findings = pipeline.hunt_release_lag()

    stored = pipeline.store.load_models("release_lag_findings", ReleaseLagFinding)
    assert findings == stored
    assert stored[0].status == "confirmed_lag"


def test_pipeline_ranks_release_lag_libraries_by_presence(tmp_path: Path) -> None:
    pipeline = Pipeline(Settings(database=tmp_path / "test.db"))
    pipeline.store.replace_models(
        "canonical_mods",
        [
            CanonicalMod(
                canonical_id="provider:curseforge:404465",
                curseforge_project_ids=["404465"],
                aliases=["FTB Library"],
            )
        ],
        key=lambda item: item.canonical_id,
    )
    pipeline.store.replace_models(
        "modpack_components",
        [
            ModpackComponent(
                modpack_file_id=f"curseforge:pack-file-{index}",
                mod_project_id="curseforge:404465",
                mod_file_id=f"curseforge:file-{index}",
                provider="curseforge",
                provider_project_id="404465",
                mod_name="FTB Library",
                mod_version="2101.1.14",
                resolution_status="resolved",
                requires_manual_review=False,
            )
            for index in range(3)
        ],
        key=lambda item: f"{item.modpack_file_id}:{item.mod_project_id}:{item.mod_file_id}",
    )

    ranked = pipeline.rank_release_lag_libraries(top=50)

    stored = pipeline.store.load_models("release_lag_libraries", ReleaseLagLibrary)
    assert ranked == stored
    assert stored[0].modpack_release_count == 3
