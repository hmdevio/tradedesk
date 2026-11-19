
"""
Centralized application configuration.

Keep environment-specific values out of source code. In production, inject
secrets through the hosting platform's secrets manager rather than a file.
"""

from functools import lru_cache
from urllib.parse import urlsplit

from pydantic import model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


ALLOWED_ENVIRONMENTS = {"development", "test", "production"}
MIN_SECRET_KEY_LENGTH = 32
# Values copied from .env.example must never run.
PLACEHOLDER_SECRETS = {"replace-with-a-long-random-secret-before-running"}


class Settings(BaseSettings):
    """Typed settings loaded from environment variables and optional .env."""

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    app_name: str = "TradeDesk"
    # No default (audit finding S5): a missing ENVIRONMENT used to mean
    # "development", which silently allowed an empty SECRET_KEY, open /docs
    # and no rate limiting. It must now be set explicitly.
    environment: str | None = None
    secret_key: str = str()
    database_url: str = "sqlite:///./tradedesk.db"
    access_token_minutes: int = 30
    # Absolute session lifetime: "Stay signed in" can renew a session only
    # until this many hours after the original sign-in.
    session_max_hours: int = 12
    cors_origins: str = ""
    redis_url: str = ""
    trusted_proxy_cidrs: str = ""

    # Email verification and application URL settings.
    app_base_url: str = "http://localhost:8000"
    email_verification_minutes: int = 30
    password_reset_minutes: int = 30

    # SMTP delivery settings.
    smtp_host: str = ""
    smtp_port: int = 587
    smtp_username: str = ""
    smtp_password: str = ""
    smtp_from_email: str = ""
    smtp_use_starttls: bool = True
    smtp_use_ssl: bool = False

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

    @model_validator(mode="after")
    def validate_core_configuration(self) -> "Settings":
        """Refuse to start with unsafe defaults (audit finding S5)."""
        environment = (self.environment or "").strip().lower()
        if environment not in ALLOWED_ENVIRONMENTS:
            raise ValueError(
                "ENVIRONMENT must be set to one of: "
                + ", ".join(sorted(ALLOWED_ENVIRONMENTS))
            )
        self.environment = environment

        secret = self.secret_key.strip()
        if len(secret) < MIN_SECRET_KEY_LENGTH or secret in PLACEHOLDER_SECRETS:
            raise ValueError(
                f"SECRET_KEY must be a random value of at least "
                f"{MIN_SECRET_KEY_LENGTH} characters in every environment"
            )

        if self.access_token_minutes <= 0:
            raise ValueError("ACCESS_TOKEN_MINUTES must be greater than zero")
        if self.session_max_hours <= 0:
            raise ValueError("SESSION_MAX_HOURS must be greater than zero")
        if self.access_token_minutes > self.session_max_hours * 60:
            raise ValueError(
                "ACCESS_TOKEN_MINUTES cannot exceed SESSION_MAX_HOURS"
            )
        return self

    @model_validator(mode="after")
    def validate_email_configuration(self) -> "Settings":
        """Reject unsafe or incomplete email configuration."""

        is_production = (
            self.environment.strip().lower() == "production"
        )

        # Verification links must have a positive expiration period.
        if self.email_verification_minutes <= 0:
            raise ValueError(
                "EMAIL_VERIFICATION_MINUTES must be greater than zero"
            )

        # Password reset links must have a positive expiration period.
        if self.password_reset_minutes <= 0:
            raise ValueError(
                "PASSWORD_RESET_MINUTES must be greater than zero"
            )

        # SMTP ports must be valid TCP port numbers.
        if not 1 <= self.smtp_port <= 65535:
            raise ValueError(
                "SMTP_PORT must be between 1 and 65535"
            )

        # An SMTP connection cannot use implicit TLS and STARTTLS together.
        if self.smtp_use_ssl and self.smtp_use_starttls:
            raise ValueError(
                "Configure either SMTP implicit TLS or STARTTLS, not both"
            )

        # SMTP authentication requires both credentials or neither.
        if bool(self.smtp_username) != bool(self.smtp_password):
            raise ValueError(
                "SMTP_USERNAME and SMTP_PASSWORD must be configured together"
            )

        # Never send SMTP authentication credentials over an unencrypted
        # connection.
        if self.smtp_username and not (
            self.smtp_use_ssl or self.smtp_use_starttls
        ):
            raise ValueError(
                "SMTP authentication requires SSL or STARTTLS"
            )

        if is_production:
            # Production verification links must use HTTPS.
            try:
                parsed_url = urlsplit(self.app_base_url)
                hostname = parsed_url.hostname
                parsed_url.port
            except ValueError as exc:
                raise ValueError(
                    "APP_BASE_URL must be a valid URL"
                ) from exc

            if (
                parsed_url.scheme.lower() != "https"
                or not hostname
                or parsed_url.username is not None
                or parsed_url.password is not None
                or parsed_url.query
                or parsed_url.fragment
            ):
                raise ValueError(
                    "Production APP_BASE_URL must be an HTTPS URL "
                    "without credentials, query parameters, or fragments"
                )

            # Production must have a configured SMTP host.
            if not self.smtp_host.strip():
                raise ValueError(
                    "SMTP_HOST is required in production"
                )

            # Production must have a configured sender address.
            if not self.smtp_from_email.strip():
                raise ValueError(
                    "SMTP_FROM_EMAIL is required in production"
                )

            # Production email must always use encrypted transport,
            # even if the SMTP server does not require authentication.
            if not (
                self.smtp_use_ssl or self.smtp_use_starttls
            ):
                raise ValueError(
                    "Production SMTP requires SSL or STARTTLS"
                )

        return self


@lru_cache
def get_settings() -> Settings:
    """Cache settings so all modules use a consistent configuration."""
    return Settings()
