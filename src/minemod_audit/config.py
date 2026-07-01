from pathlib import Path
from typing import Literal

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
        populate_by_name=True,
    )

    curseforge_api_key: str | None = Field(default=None, alias="CURSEFORGE_API_KEY")
    curseforge_enabled: Literal["auto", "true", "false"] = Field(
        default="auto",
        alias="CURSEFORGE_ENABLED",
    )
    curseforge_base_url: str = Field(
        default="https://api.curseforge.com",
        alias="CURSEFORGE_BASE_URL",
    )
    github_token: str | None = Field(default=None, alias="GITHUB_TOKEN")
    nvd_api_key: str | None = Field(default=None, alias="NVD_API_KEY")
    modrinth_enabled: bool = Field(default=True, alias="MODRINTH_ENABLED")
    modrinth_base_url: str = Field(
        default="https://api.modrinth.com/v2",
        alias="MODRINTH_BASE_URL",
    )
    modrinth_contact_email: str | None = Field(default=None, alias="MODRINTH_CONTACT_EMAIL")
    modrinth_requests_per_minute: int = Field(default=120, alias="MODRINTH_REQUESTS_PER_MINUTE")
    provider_priority: str = Field(default="modrinth,curseforge", alias="PROVIDER_PRIORITY")

    database: Path = Path("data/minemod.sqlite")
    output_directory: Path = Path("output")
    cache_directory: Path = Path("cache/http")
    timeout_seconds: float = 30.0
    concurrency: int = 4
    log_level: Literal["DEBUG", "INFO", "WARNING", "ERROR"] = "INFO"


def load_settings(
    *,
    database: Path | None = None,
    output_directory: Path | None = None,
    verbose: bool = False,
) -> Settings:
    settings = Settings()
    if database is not None:
        settings.database = database
    if output_directory is not None:
        settings.output_directory = output_directory
    if verbose:
        settings.log_level = "DEBUG"
    return settings
