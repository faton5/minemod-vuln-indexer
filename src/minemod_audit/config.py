from pathlib import Path
from typing import Literal

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", extra="ignore")

    curseforge_api_key: str | None = Field(default=None, alias="CURSEFORGE_API_KEY")
    github_token: str | None = Field(default=None, alias="GITHUB_TOKEN")
    nvd_api_key: str | None = Field(default=None, alias="NVD_API_KEY")

    database: Path = Path("data/minemod-audit.db")
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
