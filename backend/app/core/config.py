"""Konfiguracja aplikacji: wyłącznie ze zmiennych środowiskowych (.env)."""

from __future__ import annotations

from datetime import datetime
from functools import lru_cache
from ipaddress import IPv4Network, IPv6Network, ip_network
from pathlib import Path

from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    app_env: str = "development"
    log_level: str = "INFO"

    # Tryb demo jest domyślnie wyłączony. Patrz docs/ARCHITECTURE.md, sekcja 3.
    demo_mode: bool = False
    demo_approval_expires_at: datetime | None = None
    demo_lab_cidr: str = "172.30.99.0/24"

    postgres_user: str = "sentinel"
    postgres_password: str = ""
    postgres_db: str = "sentinel"
    postgres_host: str = "db"
    postgres_port: int = 5432
    database_url_override: str | None = Field(default=None, alias="DATABASE_URL")

    redis_url: str = "redis://redis:6379/0"

    scope_file: Path = Path("/app/rules/scope.yaml")
    rules_dir: Path = Path("/app/rules")

    # Feedy: offline = snapshoty z plików (domyślnie), online = pobieranie z sieci.
    feeds_mode: str = "offline"
    feeds_dir: Path = Path("/app/data/feeds")
    # Miniaturowy zestaw demo używany przez seed-demo, gdy nie ma pobranych snapshotów.
    demo_feeds_dir: Path = Path("/app/demo-feeds")
    # Fikcyjny inwentarz demo-lab importowany przez seed-demo.
    demo_assets_file: Path = Path("/app/demo-lab/assets.csv")
    nvd_api_key: str = ""

    # Powiadomienia: puste wartości oznaczają kanał wyłączony.
    smtp_host: str = ""
    smtp_port: int = 587
    smtp_user: str = ""
    smtp_password: str = ""
    smtp_from: str = ""
    notify_email_to: str = ""
    slack_webhook_url: str = ""
    teams_webhook_url: str = ""

    # LLM: inferencja lokalna przez Ollamę. Pusty LLM_MODEL = model wyłączony, system
    # pokazuje wtedy wyjaśnienia z szablonu.
    ollama_url: str = "http://ollama:11434"
    llm_model: str = ""
    llm_num_ctx: int = 4096
    llm_num_thread: int = 0
    ollama_keep_alive: str = "-1"
    llm_timeout_seconds: float = 300.0
    # Zewnętrzny LLM: domyślnie WYŁĄCZONY. Dostaje wyłącznie dane zanonimizowane.
    external_llm_enabled: bool = False
    external_llm_url: str = ""
    external_llm_model: str = ""
    external_llm_api_key: str = ""

    api_cors_origins: str = "http://localhost:8080,http://localhost:5173"

    @field_validator("demo_approval_expires_at", mode="before")
    @classmethod
    def _empty_as_none(cls, value: object) -> object:
        return None if value == "" else value

    @property
    def database_url(self) -> str:
        if self.database_url_override:
            return self.database_url_override
        return (
            f"postgresql+psycopg://{self.postgres_user}:{self.postgres_password}"
            f"@{self.postgres_host}:{self.postgres_port}/{self.postgres_db}"
        )

    @property
    def cors_origins(self) -> list[str]:
        return [o.strip() for o in self.api_cors_origins.split(",") if o.strip()]

    @property
    def demo_lab_network(self) -> IPv4Network | IPv6Network:
        return ip_network(self.demo_lab_cidr, strict=True)


@lru_cache
def get_settings() -> Settings:
    return Settings()
