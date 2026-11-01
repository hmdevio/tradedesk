"""Alembic environment using the application's configured SQLAlchemy engine."""
from logging.config import fileConfig

from alembic import context

from app.database import Base, engine
import app.models  # noqa: F401 - register every model with Base.metadata

config = context.config
if config.config_file_name is not None:
    fileConfig(config.config_file_name)

target_metadata = Base.metadata


def _schema_options(dialect_name: str) -> dict:
    """Keep PostgreSQL migration bookkeeping alongside TradeDesk tables."""
    if dialect_name == "postgresql":
        return {"version_table_schema": "tradedesk"}
    return {}


def run_migrations_offline() -> None:
    """Render migrations without opening a database connection."""
    context.configure(
        url=str(engine.url),
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
        compare_type=True,
        **_schema_options(engine.dialect.name),
    )
    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    """Run migrations through the application's configured SQLAlchemy engine."""
    supplied_connection = config.attributes.get("connection")
    if supplied_connection is not None:
        connection = supplied_connection
        context.configure(
            connection=connection,
            target_metadata=target_metadata,
            compare_type=True,
            **_schema_options(connection.dialect.name),
        )
        with context.begin_transaction():
            context.run_migrations()
        return

    with engine.connect() as connection:
        context.configure(
            connection=connection,
            target_metadata=target_metadata,
            compare_type=True,
            **_schema_options(connection.dialect.name),
        )
        with context.begin_transaction():
            context.run_migrations()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
