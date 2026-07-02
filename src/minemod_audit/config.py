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
    security_lookback_days: int = Field(default=180, alias="SECURITY_LOOKBACK_DAYS")
    gemini_api_key: str | None = Field(default=None, alias="GEMINI_API_KEY")
    gemini_ai_enabled: bool = Field(default=False, alias="GEMINI_AI_ENABLED")
    gemini_triage_model: str = Field(
        default="gemini-3.1-flash-lite",
        alias="GEMINI_TRIAGE_MODEL",
    )
    gemini_review_model: str = Field(default="gemini-3.5-flash", alias="GEMINI_REVIEW_MODEL")
    gemini_max_candidates_per_run: int = Field(
        default=20,
        alias="GEMINI_MAX_CANDIDATES_PER_RUN",
    )
    gemini_max_review_calls_per_run: int = Field(
        default=3,
        alias="GEMINI_MAX_REVIEW_CALLS_PER_RUN",
    )
    gemini_max_input_chars: int = Field(default=30000, alias="GEMINI_MAX_INPUT_CHARS")
    gemini_max_output_tokens: int = Field(default=1200, alias="GEMINI_MAX_OUTPUT_TOKENS")
    gemini_cache_enabled: bool = Field(default=True, alias="GEMINI_CACHE_ENABLED")
    gemini_prompt_version: str = Field(
        default="security-triage-v1",
        alias="GEMINI_PROMPT_VERSION",
    )

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
