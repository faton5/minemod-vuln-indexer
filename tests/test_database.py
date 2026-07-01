from pathlib import Path

from minemod_audit.database import DataStore
from minemod_audit.models import ModpackComponent


def test_replace_models_keeps_last_payload_for_duplicate_keys(tmp_path: Path) -> None:
    store = DataStore(tmp_path / "test.sqlite")
    first = ModpackComponent(
        modpack_file_id="pack-version",
        mod_project_id="mod-project",
        mod_file_id="mod-version",
        required=True,
    )
    second = ModpackComponent(
        modpack_file_id="pack-version",
        mod_project_id="mod-project",
        mod_file_id="mod-version",
        required=False,
    )

    store.replace_models(
        "modpack_components",
        [first, second],
        key=lambda item: f"{item.modpack_file_id}:{item.mod_project_id}:{item.mod_file_id}",
    )

    stored = store.load_models("modpack_components", ModpackComponent)
    assert len(stored) == 1
    assert stored[0].required is False


def test_append_models_keeps_last_payload_for_duplicate_keys(tmp_path: Path) -> None:
    store = DataStore(tmp_path / "test.sqlite")
    first = ModpackComponent(
        modpack_file_id="pack-version",
        mod_project_id="mod-project",
        mod_file_id="mod-version",
        required=True,
    )
    second = ModpackComponent(
        modpack_file_id="pack-version",
        mod_project_id="mod-project",
        mod_file_id="mod-version",
        required=False,
    )

    store.append_models(
        "modpack_components",
        [first, second],
        key=lambda item: f"{item.modpack_file_id}:{item.mod_project_id}:{item.mod_file_id}",
    )

    stored = store.load_models("modpack_components", ModpackComponent)
    assert len(stored) == 1
    assert stored[0].required is False
