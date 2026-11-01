
"""Database engine and session helpers."""
from collections.abc import Generator
from pathlib import Path

from sqlalchemy import create_engine
from sqlalchemy.orm import DeclarativeBase, Session, sessionmaker

from app.config import get_settings


settings = get_settings()

# SQLite is retained for local development and automated tests.
if settings.database_url.startswith("sqlite"):
    connect_args = {"check_same_thread": False}

# PostgreSQL connections must use verified TLS and a client certificate.
elif settings.database_url.startswith(("postgresql://", "postgresql+")):
    certificate_settings = {
        "sslrootcert": settings.database_sslrootcert,
        "sslcert": settings.database_sslcert,
        "sslkey": settings.database_sslkey,
        # Existing PostgreSQL application tables live in the tradedesk schema.
        # Keep unqualified ORM queries pointed there instead of public.
        "options": "-csearch_path=tradedesk,public",
    }

    missing = [
        name for name, value in certificate_settings.items()
        if not value.strip()
    ]
    if missing:
        raise RuntimeError(
            "PostgreSQL mTLS configuration is incomplete. "
            "Set these environment variables: "
            + ", ".join(missing)
        )

    for name, value in certificate_settings.items():
        if not Path(value).is_file():
            raise RuntimeError(
                f"PostgreSQL mTLS certificate file does not exist: {name}"
            )

    if settings.database_sslmode != "verify-full":
        raise RuntimeError(
            "PostgreSQL connections must use database_sslmode=verify-full."
        )

    connect_args = {
        "sslmode": settings.database_sslmode,
        "sslrootcert": settings.database_sslrootcert,
        "sslcert": settings.database_sslcert,
        "sslkey": settings.database_sslkey,
    }

else:
    raise RuntimeError("Unsupported database URL configuration.")

# pool_pre_ping helps detect stale connections.
engine = create_engine(
    settings.database_url,
    connect_args=connect_args,
    pool_pre_ping=True,
)

SessionLocal = sessionmaker(
    bind=engine,
    autoflush=False,
    autocommit=False,
    expire_on_commit=False,
)


class Base(DeclarativeBase):
    """Base class for ORM models."""


def get_db() -> Generator[Session, None, None]:
    """Yield one request-scoped session and always close it."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
