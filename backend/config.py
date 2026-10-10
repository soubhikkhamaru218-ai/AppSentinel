"""
AppSentinel // Backend Configuration
Loads environment variables with pydantic-settings for validation.
"""

import os
from pathlib import Path
from functools import lru_cache

from pydantic_settings import BaseSettings
from pydantic import Field


# Project root is two levels up from backend/config.py
PROJECT_ROOT = Path(__file__).resolve().parent.parent


class Settings(BaseSettings):
    """Centralized, validated configuration for the AppSentinel backend."""

    # --- Server ---
    app_env: str = Field(default="development")
    app_port: int = Field(default=8000)
    app_host: str = Field(default="0.0.0.0")
    frontend_origin: str = Field(default="http://localhost:8088")
    cors_origins: str = Field(default="")

    # --- Database ---
    database_url: str = Field(default="sqlite:///./storage/appsentinel.db")

    # --- External API Keys (all optional — services degrade gracefully) ---
    virustotal_api_key: str = Field(default="")
    urlscan_api_key: str = Field(default="")
    google_safe_browsing_api_key: str = Field(default="")   # https://console.cloud.google.com → Safe Browsing API
    gemini_api_key: str = Field(default="")
    ai_model: str = Field(default="gemini-2.5-flash")
    ai_model_timeout_seconds: float = Field(default=12.0)
    ai_total_timeout_seconds: float = Field(default=25.0)
    mobsf_url: str = Field(default="http://localhost:8001")
    mobsf_api_key: str = Field(default="")
    mobsf_timeout_seconds: float = Field(default=15.0)
    mobsf_max_retries: int = Field(default=0)
    mobsf_poll_interval_seconds: float = Field(default=2.0)

    # --- Upload Limits ---
    max_apk_size_mb: int = Field(default=50)
    upload_chunk_size_bytes: int = Field(default=1024 * 1024)
    upload_dir: str = Field(default="./storage/uploads")

    # --- Request Protection ---
    scan_rate_limit_max: int = Field(default=60)
    scan_rate_limit_window_seconds: float = Field(default=60.0)
    scan_concurrency_limit: int = Field(default=4)

    # --- Logging ---
    log_level: str = Field(default="INFO")

    model_config = {
        "env_file": str(PROJECT_ROOT / ".env"),
        "env_file_encoding": "utf-8",
        "extra": "ignore",
    }

    @property
    def max_apk_size_bytes(self) -> int:
        return self.max_apk_size_mb * 1024 * 1024

    @property
    def upload_path(self) -> Path:
        p = Path(self.upload_dir)
        if not p.is_absolute():
            p = PROJECT_ROOT / p
        p.mkdir(parents=True, exist_ok=True)
        return p

    @property
    def db_path(self) -> Path:
        """Return the resolved path to the SQLite database file."""
        if not self.database_url.strip().lower().startswith("sqlite"):
            raise ValueError("db_path is only available when DATABASE_URL uses SQLite.")

        raw = self.database_url.replace("sqlite:///", "")
        p = Path(raw)
        if not p.is_absolute():
            p = PROJECT_ROOT / p
        p.parent.mkdir(parents=True, exist_ok=True)
        return p

    @property
    def is_sqlite_database(self) -> bool:
        return self.database_url.strip().lower().startswith("sqlite")

    @property
    def is_dev(self) -> bool:
        return self.app_env == "development"


@lru_cache()
def get_settings() -> Settings:
    """Singleton settings instance, cached for the lifetime of the process."""
    return Settings()
