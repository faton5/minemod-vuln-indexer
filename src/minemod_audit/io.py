from pathlib import Path
from typing import Any

import yaml


def load_yaml_mapping(path: Path) -> dict[int, dict[str, object]]:
    if not path.exists():
        return {}
    payload = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    return {int(key): dict(value) for key, value in payload.items()}


def load_yaml_list(path: Path) -> list[dict[str, Any]]:
    if not path.exists():
        return []
    payload = yaml.safe_load(path.read_text(encoding="utf-8")) or []
    if not isinstance(payload, list):
        raise ValueError(f"{path} must contain a YAML list")
    return [dict(item) for item in payload]
