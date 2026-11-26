
"""Database engine and session helpers."""
from collections.abc import Generator
from pathlib import Path

from sqlalchemy import create_engine
from sqlalchemy.orm import DeclarativeBase, Session, sessionmaker

from app.config import get_settings


settings = get_settings()


def postgres_connect_args(settings) -> dict:
    """Build PostgreSQL TLS settings. The server certificate is always verified.

    DATABASE_SSLROOTCERT is a CA file, or "system" to trust the operating
    system's certificate authorities (for hosted databases with a public
    certificate). A client certificate (mTLS) is optional, but the certificate
    and key must be set together.
    """
    if settings.database_sslmode != "verify-full":
        raise RuntimeError(
            "PostgreSQL connections must use database_sslmode=verify-full."
        )

    root_cert = settings.database_sslrootcert.strip()
    if not root_cert:
        raise RuntimeError(
            "Set DATABASE_SSLROOTCERT to a CA file or to \"system\"."
        )
    if root_cert != "system" and not Path(root_cert).is_file():
        raise RuntimeError(
            "PostgreSQL CA certificate file does not exist: database_sslrootcert"
        )

    client_cert = settings.database_sslcert.strip()
    client_key = settings.database_sslkey.strip()
    if bool(client_cert) != bool(client_key):
        raise RuntimeError(
            "Set DATABASE_SSLCERT and DATABASE_SSLKEY together, or neither."
        )

    connect_args = {
        "sslmode": "verify-full",
        "sslrootcert": root_cert,
        # Existing PostgreSQL application tables live in tradedesk, not public.
        "options": "-csearch_path=tradedesk,public",
    }
    for name, value in (("sslcert", client_cert), ("sslkey", client_key)):
        if value:
            if not Path(value).is_file():
                raise RuntimeError(
                    f"PostgreSQL client certificate file does not exist: database_{name}"
                )
            connect_args[name] = value
    return connect_args


# SQLite is retained for local development and automated tests.
if settings.database_url.startswith("sqlite"):
    connect_args = {"check_same_thread": False}

# PostgreSQL connections must use verified TLS (sslmode=verify-full).
elif settings.database_url.startswith(("postgresql://", "postgresql+")):
    connect_args = postgres_connect_args(settings)

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
