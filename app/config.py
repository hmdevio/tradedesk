
"""Centralized application configuration.

Keep environment-specific values out of source code. In production, inject
secrets through the hosting platform's secrets manager rather than a file.
"""
from functools import lru_cache
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Typed settings loaded from environment variables and optional .env."""

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    app_name: str = "TradeDesk"
    environment: str = "development"
    secret_key: str = "replace-with-a-long-random-secret-before-running"
    database_url: str = "sqlite:///./tradedesk.db"
    access_token_minutes: int = 30
    cors_origins: str = ""

    # PostgreSQL TLS/mTLS settings.
    database_sslmode: str = "verify-full"
    database_sslrootcert: str = ""
    database_sslcert: str = ""
    database_sslkey: str = ""

    @property
    def parsed_cors_origins(self) -> list[str]:
        """Parse a comma-separated allowlist. Empty means no browser origins."""
        return [
            origin.strip()
            for origin in self.cors_origins.split(",")
            if origin.strip()
        ]


@lru_cache
def get_settings() -> Settings:
    """Cache settings so all modules use a consistent configuration."""
    return Settings()
