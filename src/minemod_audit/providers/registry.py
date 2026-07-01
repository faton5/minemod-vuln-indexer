import logging

from minemod_audit.config import Settings
from minemod_audit.providers.base import ProjectProvider, ProviderStatus
from minemod_audit.providers.curseforge import CurseForgeProvider
from minemod_audit.providers.modrinth import ModrinthProvider

LOGGER = logging.getLogger(__name__)


class ProviderRegistry:
    def __init__(
        self,
        settings: Settings,
        *,
        offline: bool = False,
        refresh: bool = False,
    ) -> None:
        self.settings = settings
        self.offline = offline
        self.refresh = refresh

    def status(self) -> list[ProviderStatus]:
        statuses = self._metadata_statuses()
        statuses.extend(self._supporting_statuses())
        return statuses

    def enabled_provider_names(self, selector: str) -> list[str]:
        requested = self._requested_names(selector)
        enabled = {
            status.name.lower(): status
            for status in self._metadata_statuses()
            if status.status == "enabled"
        }
        return [name for name in self._priority() if name in requested and name in enabled]

    def build_provider(self, name: str) -> ProjectProvider:
        if name == "modrinth":
            return ModrinthProvider(self.settings, offline=self.offline, refresh=self.refresh)
        if name == "curseforge":
            return CurseForgeProvider(self.settings, offline=self.offline, refresh=self.refresh)
        raise ValueError(f"Unknown provider: {name}")

    def _metadata_statuses(self) -> list[ProviderStatus]:
        priority = self._priority()
        statuses: list[ProviderStatus] = []
        if "modrinth" in priority:
            statuses.append(
                ProviderStatus(
                    name="Modrinth",
                    status="enabled" if self.settings.modrinth_enabled else "disabled",
                    priority=priority.index("modrinth") + 1,
                    reason="Public API available"
                    if self.settings.modrinth_enabled
                    else "Disabled by config",
                )
            )
        if "curseforge" in priority:
            statuses.append(self._curseforge_status(priority.index("curseforge") + 1))
        return statuses

    def _curseforge_status(self, priority: int) -> ProviderStatus:
        configured = bool((self.settings.curseforge_api_key or "").strip())
        if self.settings.curseforge_enabled == "false":
            return ProviderStatus(
                name="CurseForge",
                status="disabled",
                priority=priority,
                reason="Disabled by config",
            )
        if not configured:
            if self.settings.curseforge_enabled == "auto":
                LOGGER.info("CurseForge provider disabled: no API key configured")
            return ProviderStatus(
                name="CurseForge",
                status="disabled",
                priority=priority,
                reason="API key not configured",
            )
        return ProviderStatus(
            name="CurseForge",
            status="enabled",
            priority=priority,
            reason="API key configured",
        )

    def _supporting_statuses(self) -> list[ProviderStatus]:
        return [
            ProviderStatus(
                name="GitHub",
                status="enabled" if self.settings.github_token else "disabled",
                priority=None,
                reason="Token configured" if self.settings.github_token else "Token not configured",
            ),
            ProviderStatus(
                name="NVD",
                status="enabled" if self.settings.nvd_api_key else "disabled",
                priority=None,
                reason=(
                    "API key configured" if self.settings.nvd_api_key else "API key not configured"
                ),
            ),
        ]

    def _priority(self) -> list[str]:
        return [
            item.strip().lower()
            for item in self.settings.provider_priority.split(",")
            if item.strip()
        ]

    @staticmethod
    def _requested_names(selector: str) -> set[str]:
        normalized = selector.strip().lower()
        if normalized == "all":
            return {"modrinth", "curseforge"}
        return {item.strip() for item in normalized.split(",") if item.strip()}
