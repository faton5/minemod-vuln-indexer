from minemod_audit.manifest import parse_manifest_json


def test_parse_curseforge_manifest_components() -> None:
    manifest = {
        "minecraft": {
            "version": "1.20.1",
            "modLoaders": [{"id": "forge-47.2.0", "primary": True}],
        },
        "files": [
            {"projectID": 111, "fileID": 222, "required": True},
            {"projectID": 333, "fileID": 444, "required": False},
        ],
    }

    parsed = parse_manifest_json(manifest)

    assert parsed.minecraft_version == "1.20.1"
    assert parsed.loader == "forge"
    assert [(item.project_id, item.file_id, item.required) for item in parsed.components] == [
        (111, 222, True),
        (333, 444, False),
    ]
