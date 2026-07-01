from minemod_audit.config import Settings
from minemod_audit.providers.registry import ProviderRegistry


def test_curseforge_is_disabled_without_api_key() -> None:
    registry = ProviderRegistry(Settings(curseforge_api_key=None, curseforge_enabled="auto"))

    statuses = registry.status()

    curseforge = next(status for status in statuses if status.name == "CurseForge")
    modrinth = next(status for status in statuses if status.name == "Modrinth")
    assert modrinth.status == "enabled"
    assert curseforge.status == "disabled"
    assert curseforge.reason == "API key not configured"


def test_curseforge_is_enabled_automatically_with_api_key() -> None:
    registry = ProviderRegistry(Settings(curseforge_api_key="secret", curseforge_enabled="auto"))

    statuses = registry.status()

    curseforge = next(status for status in statuses if status.name == "CurseForge")
    assert curseforge.status == "enabled"
    assert curseforge.reason == "API key configured"


def test_provider_selection_keeps_modrinth_first_for_all() -> None:
    registry = ProviderRegistry(Settings(curseforge_api_key="secret"))

    providers = registry.enabled_provider_names("all")

    assert providers == ["modrinth", "curseforge"]
