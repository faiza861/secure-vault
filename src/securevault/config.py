"""Settings, read from environment variables or a local .env file."""

from functools import lru_cache
from pathlib import Path
from typing import Literal

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict

ROOT = Path(__file__).resolve().parents[2]


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    storage_backend: Literal["local", "memory", "postgres"] = "local"
    data_dir: Path = ROOT / "data" / "vault"
    database_url: str = ""

    # Vercel serverless request bodies are limited to roughly 4.5 MB; stay below it.
    max_upload_bytes: int = 4 * 1024 * 1024
    min_passphrase_length: int = 10

    # Anomaly detection
    window_seconds: int = 300
    tz_offset_hours: int = 0  # local time offset used for "odd hour" checks
    model_path: Path = ROOT / "models" / "anomaly_model.json"

    # Online-guessing protection (lockout is derived from the audit log; see security/lockout.py)
    rate_limit_max_failures: int = Field(default=5, ge=1)  # per actor, per window
    rate_limit_window_seconds: int = Field(default=300, ge=1)
    lockout_seconds: int = Field(default=60, ge=1)  # first lockout; later ones grow 5x each time
    rate_limit_global_max_failures: int = Field(default=20, ge=1)  # backstop across all actors
    lockout_max_seconds: int = Field(default=900, ge=1)  # hard cap, so the owner is never locked out for good

    # Short-lived sessions (see security/session.py). SESSION_SECRET signs the tokens; it comes ONLY from the
    # environment. Unset or shorter than 32 chars -> a random per-process secret is used (sessions then do not
    # survive a restart or work across serverless instances; that fails closed, it never weakens anything).
    session_secret: str = ""
    session_ttl_seconds: int = Field(default=900, ge=30)  # absolute lifetime
    session_idle_seconds: int = Field(default=300, ge=30)  # inactivity timeout
    reauth_window_seconds: int = Field(default=300, ge=0)  # how long a verified code counts as "recent"


@lru_cache
def get_settings() -> Settings:
    return Settings()
