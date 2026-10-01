"""Application configuration.

All configuration is read from environment variables (or a ``.env`` file) via
pydantic-settings. Secrets such as ``AI_API_KEY`` and ``SECRET_KEY`` are never
hard-coded and are wrapped in ``SecretStr`` so they are not accidentally logged.
"""

from __future__ import annotations

import secrets
from functools import lru_cache
from pathlib import Path

from pydantic import SecretStr, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

BACKEND_DIR = Path(__file__).resolve().parents[2]
PROJECT_ROOT = BACKEND_DIR.parent


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=(str(PROJECT_ROOT / ".env"), str(BACKEND_DIR / ".env")),
        env_file_encoding="utf-8",
        extra="ignore",
    )

    # --- Application -----------------------------------------------------
    app_name: str = "MemTrace - AI-Assisted Windows Memory Forensics"
    environment: str = "development"
    log_level: str = "INFO"
    cors_origins: list[str] = ["http://localhost:5173", "http://localhost:8080"]

    # --- Database --------------------------------------------------------
    database_url: str = ""

    # --- Authentication --------------------------------------------------
    secret_key: SecretStr = SecretStr("")
    access_token_minutes: int = 480
    admin_username: str = "admin"
    admin_password: SecretStr = SecretStr("ChangeMe!2026")

    # --- Storage ---------------------------------------------------------
    data_dir: Path = BACKEND_DIR / "data"
    rules_dir: Path = PROJECT_ROOT / "rules"
    yara_rules_dir: Path = PROJECT_ROOT / "yara_rules"
    sample_data_dir: Path = PROJECT_ROOT / "sample_data"

    # --- Evidence intake -------------------------------------------------
    max_upload_bytes: int = 32 * 1024**3  # 32 GiB
    min_image_bytes: int = 1024 * 1024  # 1 MiB - anything smaller cannot hold a Windows kernel
    allowed_extensions: tuple[str, ...] = (".raw", ".mem", ".dmp", ".vmem")
    verify_hash_on_analysis: bool = True

    # --- Volatility ------------------------------------------------------
    volatility_cmd: str = ""  # empty = auto-detect ("vol" on PATH or the volatility3 package)
    volatility_symbols_dir: Path | None = None
    volatility_offline: bool = False
    plugin_timeout_seconds: int = 900
    plugin_max_output_bytes: int = 512 * 1024 * 1024
    analysis_workers: int = 1
    deep_scan_max_pids: int = 15
    enable_filescan: bool = False
    yara_scan_all_processes: bool = False

    # --- AI ----------------------------------------------------------------
    ai_provider: str = "deterministic"  # deterministic | openai | ollama
    ai_base_url: str = ""
    ai_model: str = ""
    ai_api_key: SecretStr = SecretStr("")
    ai_timeout_seconds: int = 60
    ai_temperature: float = 0.1
    ai_max_evidence_items: int = 40

    @field_validator("ai_provider")
    @classmethod
    def _provider(cls, v: str) -> str:
        v = v.strip().lower()
        if v not in {"deterministic", "openai", "ollama"}:
            raise ValueError("AI_PROVIDER must be one of: deterministic, openai, ollama")
        return v

    @field_validator("allowed_extensions", mode="before")
    @classmethod
    def _exts(cls, v: object) -> object:
        if isinstance(v, str):
            return tuple(e.strip().lower() for e in v.split(",") if e.strip())
        return v

    # --- Derived paths ---------------------------------------------------
    @property
    def evidence_dir(self) -> Path:
        return self.data_dir / "evidence"

    @property
    def upload_tmp_dir(self) -> Path:
        return self.data_dir / "tmp"

    @property
    def work_dir(self) -> Path:
        return self.data_dir / "work"

    @property
    def reports_dir(self) -> Path:
        return self.data_dir / "reports"

    @property
    def user_yara_dir(self) -> Path:
        return self.data_dir / "yara"

    @property
    def effective_database_url(self) -> str:
        if self.database_url:
            return self.database_url
        return f"sqlite:///{(self.data_dir / 'forensics.db').as_posix()}"

    def ensure_directories(self) -> None:
        for d in (self.data_dir, self.evidence_dir, self.upload_tmp_dir, self.work_dir,
                  self.reports_dir, self.user_yara_dir):
            d.mkdir(parents=True, exist_ok=True)


_generated_secret = secrets.token_urlsafe(48)
secret_was_generated = False


@lru_cache
def get_settings() -> Settings:
    global secret_was_generated
    settings = Settings()
    if not settings.secret_key.get_secret_value():
        # Tokens become invalid after a restart; acceptable for development, warned at startup.
        settings.secret_key = SecretStr(_generated_secret)
        secret_was_generated = True
    return settings
