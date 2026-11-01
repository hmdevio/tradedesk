"""Smoke-test the auth-session migration against an isolated SQLite database."""
from pathlib import Path

from alembic import command
from alembic.config import Config
from sqlalchemy import create_engine, inspect


ROOT = Path(__file__).resolve().parents[1]
ALEMBIC_INI = ROOT / "alembic.ini"


def _config():
    config = Config(str(ALEMBIC_INI))
    config.set_main_option("script_location", str(ROOT / "migrations"))
    return config


def test_auth_sessions_upgrade_and_downgrade(tmp_path):
    database = tmp_path / "migration-test.db"
    test_engine = create_engine(f"sqlite:///{database}")

    with test_engine.begin() as connection:
        # The migration adds auth_sessions to an existing users table.
        connection.exec_driver_sql(
            """
            CREATE TABLE users (
                id INTEGER NOT NULL PRIMARY KEY,
                email VARCHAR(320) NOT NULL UNIQUE,
                password_hash VARCHAR(255) NOT NULL,
                created_at DATETIME NOT NULL
            )
            """
        )
        config = _config()
        config.attributes["connection"] = connection
        command.upgrade(config, "head")

        inspector = inspect(connection)
        assert "auth_sessions" in inspector.get_table_names()
        columns = {column["name"]: column for column in inspector.get_columns("auth_sessions")}
        assert set(columns) == {"id", "user_id", "expires_at", "revoked_at", "created_at"}
        assert columns["user_id"]["nullable"] is False
        assert columns["revoked_at"]["nullable"] is True

        foreign_keys = inspector.get_foreign_keys("auth_sessions")
        assert any(
            fk["referred_table"] == "users"
            and fk["constrained_columns"] == ["user_id"]
            and fk["options"].get("ondelete") == "CASCADE"
            for fk in foreign_keys
        )

        indexes = {index["name"] for index in inspector.get_indexes("auth_sessions")}
        assert indexes == {"ix_auth_sessions_user_id", "ix_auth_sessions_user_expiry"}

        command.downgrade(config, "base")
        assert "auth_sessions" not in inspect(connection).get_table_names()

    test_engine.dispose()
