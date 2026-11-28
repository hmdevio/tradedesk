"""Smoke-test database migrations against an isolated SQLite database."""

from pathlib import Path

import pytest
from alembic import command
from alembic.config import Config
from sqlalchemy import create_engine, inspect


ROOT = Path(__file__).resolve().parents[1]
ALEMBIC_INI = ROOT / "alembic.ini"


def _config():
    """Create an Alembic configuration for the project migrations."""
    config = Config(str(ALEMBIC_INI))
    config.set_main_option(
        "script_location",
        str(ROOT / "migrations"),
    )
    return config


def _create_legacy_customers_table(connection):
    """Create the existing customer table without the new unique index."""
    connection.exec_driver_sql(
        """
        CREATE TABLE customers (
            id INTEGER NOT NULL PRIMARY KEY,
            user_id INTEGER NOT NULL,
            name VARCHAR(120) NOT NULL,
            email VARCHAR(320),
            FOREIGN KEY(user_id)
                REFERENCES users(id)
                ON DELETE CASCADE
        )
        """
    )
    _create_legacy_job_tables(connection)


def _create_legacy_job_tables(connection):
    """Create the core jobs and service_reports tables (not Alembic-managed).

    The worksheet migration (20261118_02) references both, as the real
    database does.
    """
    connection.exec_driver_sql(
        """
        CREATE TABLE jobs (
            id INTEGER NOT NULL PRIMARY KEY,
            user_id INTEGER NOT NULL,
            customer_id INTEGER NOT NULL,
            title VARCHAR(160) NOT NULL,
            trade_type VARCHAR(80) NOT NULL,
            status VARCHAR(30) NOT NULL,
            created_at DATETIME NOT NULL,
            FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE,
            FOREIGN KEY(customer_id) REFERENCES customers(id) ON DELETE CASCADE
        )
        """
    )
    connection.exec_driver_sql(
        """
        CREATE TABLE service_reports (
            id INTEGER NOT NULL PRIMARY KEY,
            job_id INTEGER NOT NULL,
            original_notes TEXT NOT NULL,
            generated_content TEXT NOT NULL,
            status VARCHAR(20) NOT NULL,
            created_at DATETIME NOT NULL,
            updated_at DATETIME NOT NULL,
            FOREIGN KEY(job_id) REFERENCES jobs(id) ON DELETE CASCADE
        )
        """
    )


def _customer_email_index_exists(connection):
    """Check the expression index through SQLite's schema catalog."""
    return (
        connection.exec_driver_sql(
            """
            SELECT 1
            FROM sqlite_master
            WHERE type = 'index'
              AND tbl_name = 'customers'
              AND name = 'uq_customers_user_email_normalized'
            """
        ).scalar_one_or_none()
        is not None
    )


def _has_unique_token_hash(connection):
    """Check that token_hash has a unique constraint or unique index."""
    sqlite_indexes = connection.exec_driver_sql(
        "PRAGMA index_list('email_verification_tokens')"
    ).fetchall()

    for index in sqlite_indexes:
        index_name = index[1]
        is_unique = bool(index[2])
        is_partial = bool(index[4])

        if not is_unique or is_partial:
            continue

        # SQLite creates an internal unique index for table-level UNIQUE.
        # Quote the identifier returned by SQLite before using it in PRAGMA.
        quoted_index_name = '"' + index_name.replace('"', '""') + '"'

        index_columns = connection.exec_driver_sql(
            f"PRAGMA index_info({quoted_index_name})"
        ).fetchall()

        indexed_columns = [column[2] for column in index_columns]

        if indexed_columns == ["token_hash"]:
            return True

    return False


def _prepare_existing_token_table(connection, config):
    """Prepare a valid pre-existing token table at the prior revision."""
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

    _create_legacy_customers_table(connection)

    # Apply the preceding migration before creating the existing token table.
    command.upgrade(config, "20261030_01")

    connection.exec_driver_sql(
        """
        CREATE TABLE email_verification_tokens (
            id INTEGER NOT NULL PRIMARY KEY,
            user_id INTEGER NOT NULL,
            token_hash VARCHAR(64) NOT NULL,
            expires_at DATETIME NOT NULL,
            used_at DATETIME,
            created_at DATETIME NOT NULL,
            FOREIGN KEY(user_id)
                REFERENCES users(id)
                ON DELETE CASCADE
        )
        """
    )


def test_auth_sessions_and_email_verification_upgrade_and_downgrade(
    tmp_path,
):
    """Verify the migration chain creates and removes expected structures."""
    database = tmp_path / "migration-test.db"
    test_engine = create_engine(f"sqlite:///{database}")

    try:
        with test_engine.begin() as connection:
            # Create the legacy users table that existed before migrations.
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

            _create_legacy_customers_table(connection)

            config = _config()
            config.attributes["connection"] = connection

            # Apply the complete migration chain.
            command.upgrade(config, "head")

            inspector = inspect(connection)
            table_names = set(inspector.get_table_names())

            # SQLite's SQLAlchemy inspector skips expression-based indexes.
            # Query sqlite_master directly to verify the migration-created index.
            assert _customer_email_index_exists(connection)

            # Confirm the auth-session table was created.
            assert "auth_sessions" in table_names

            auth_columns = {
                column["name"]: column
                for column in inspector.get_columns("auth_sessions")
            }

            assert set(auth_columns) == {
                "id",
                "user_id",
                "expires_at",
                "revoked_at",
                "created_at",
            }

            assert auth_columns["user_id"]["nullable"] is False
            assert auth_columns["revoked_at"]["nullable"] is True

            auth_foreign_keys = inspector.get_foreign_keys(
                "auth_sessions"
            )

            assert any(
                foreign_key["referred_table"] == "users"
                and foreign_key["constrained_columns"] == ["user_id"]
                and foreign_key["options"].get("ondelete") == "CASCADE"
                for foreign_key in auth_foreign_keys
            )

            auth_indexes = {
                index["name"]
                for index in inspector.get_indexes("auth_sessions")
            }

            assert auth_indexes == {
                "ix_auth_sessions_user_id",
                "ix_auth_sessions_user_expiry",
            }

            # Confirm email verification fields were added to users.
            user_columns = {
                column["name"]: column
                for column in inspector.get_columns("users")
            }

            assert "email_verified" in user_columns
            assert "email_verified_at" in user_columns
            assert user_columns["email_verified"]["nullable"] is False
            assert user_columns["email_verified_at"]["nullable"] is True

            # Confirm the email verification token table was created.
            assert "email_verification_tokens" in table_names

            token_columns = {
                column["name"]: column
                for column in inspector.get_columns(
                    "email_verification_tokens"
                )
            }

            assert set(token_columns) == {
                "id",
                "user_id",
                "token_hash",
                "expires_at",
                "used_at",
                "created_at",
            }

            assert token_columns["user_id"]["nullable"] is False
            assert token_columns["token_hash"]["nullable"] is False
            assert token_columns["expires_at"]["nullable"] is False
            assert token_columns["used_at"]["nullable"] is True

            token_foreign_keys = inspector.get_foreign_keys(
                "email_verification_tokens"
            )

            assert any(
                foreign_key["referred_table"] == "users"
                and foreign_key["constrained_columns"] == ["user_id"]
                and foreign_key["options"].get("ondelete") == "CASCADE"
                for foreign_key in token_foreign_keys
            )

            # Confirm only the intended explicit indexes exist.
            token_indexes = {
                index["name"]
                for index in inspector.get_indexes(
                    "email_verification_tokens"
                )
            }

            assert token_indexes == {
                "ix_email_verification_tokens_user_id",
                "ix_email_verification_tokens_user_expiry",
            }

            # Confirm token hashes are uniquely constrained.
            assert _has_unique_token_hash(connection)

            # Downgrade the entire migration chain.
            command.downgrade(config, "base")

            downgraded_inspector = inspect(connection)
            downgraded_tables = set(
                downgraded_inspector.get_table_names()
            )

            assert "customers" in downgraded_tables

            # Verify the expression index was removed by downgrade.
            assert not _customer_email_index_exists(connection)

            assert "auth_sessions" not in downgraded_tables
            assert "email_verification_tokens" not in downgraded_tables

            downgraded_user_columns = {
                column["name"]
                for column in downgraded_inspector.get_columns("users")
            }

            assert "email_verified" not in downgraded_user_columns
            assert "email_verified_at" not in downgraded_user_columns

            # The original users table remains after all feature migrations
            # have been rolled back.
            assert downgraded_user_columns == {
                "id",
                "email",
                "password_hash",
                "created_at",
            }

    finally:
        test_engine.dispose()


def test_existing_email_verification_table_is_preserved(
    tmp_path,
):
    """Reuse pre-existing token storage without damaging its data."""
    database = tmp_path / "existing-verification-table.db"
    test_engine = create_engine(f"sqlite:///{database}")

    existing_token_hash = "a" * 64

    try:
        with test_engine.begin() as connection:
            # Simulate the legacy users table.
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

            _create_legacy_customers_table(connection)

            connection.exec_driver_sql(
                """
                INSERT INTO users (
                    id, email, password_hash, created_at
                )
                VALUES (
                    1, 'existing@example.com', 'test-hash',
                    '2026-11-04 12:00:00'
                )
                """
            )

            # Simulate a token table created before Alembic.
            connection.exec_driver_sql(
                """
                CREATE TABLE email_verification_tokens (
                    id INTEGER NOT NULL PRIMARY KEY,
                    user_id INTEGER NOT NULL,
                    token_hash VARCHAR(64) NOT NULL UNIQUE,
                    expires_at DATETIME NOT NULL,
                    used_at DATETIME,
                    created_at DATETIME NOT NULL,
                    FOREIGN KEY(user_id)
                        REFERENCES users(id)
                        ON DELETE CASCADE
                )
                """
            )

            connection.exec_driver_sql(
                """
                CREATE INDEX ix_email_verification_tokens_user_id
                ON email_verification_tokens (user_id)
                """
            )

            connection.exec_driver_sql(
                """
                CREATE INDEX ix_email_verification_tokens_user_expiry
                ON email_verification_tokens (user_id, expires_at)
                """
            )

            # Preserve a real existing record throughout the migration.
            connection.exec_driver_sql(
                """
                INSERT INTO email_verification_tokens (
                    id, user_id, token_hash, expires_at,
                    used_at, created_at
                )
                VALUES (
                    1, 1, ?, '2026-11-05 12:00:00',
                    NULL, '2026-11-04 12:00:00'
                )
                """,
                (existing_token_hash,),
            )

            config = _config()
            config.attributes["connection"] = connection

            # Apply migrations to the partially initialized database.
            command.upgrade(config, "head")

            inspector = inspect(connection)

            # The existing token table must remain intact.
            assert "email_verification_tokens" in inspector.get_table_names()

            token_columns = {
                column["name"]
                for column in inspector.get_columns(
                    "email_verification_tokens"
                )
            }

            assert token_columns == {
                "id",
                "user_id",
                "token_hash",
                "expires_at",
                "used_at",
                "created_at",
            }

            # The existing token record must not be lost or changed.
            token = connection.exec_driver_sql(
                """
                SELECT id, user_id, token_hash
                FROM email_verification_tokens
                WHERE id = 1
                """
            ).one()

            assert token.id == 1
            assert token.user_id == 1
            assert token.token_hash == existing_token_hash

            # Existing indexes must not be duplicated or replaced.
            token_indexes = {
                index["name"]
                for index in inspector.get_indexes(
                    "email_verification_tokens"
                )
            }

            assert token_indexes == {
                "ix_email_verification_tokens_user_id",
                "ix_email_verification_tokens_user_expiry",
            }

            # Existing uniqueness must remain enforced.
            assert _has_unique_token_hash(connection), (
                "The existing token_hash uniqueness constraint "
                "was not preserved."
            )

            # Existing accounts must remain verified after migration.
            existing_user = connection.exec_driver_sql(
                """
                SELECT email_verified, email_verified_at
                FROM users
                WHERE id = 1
                """
            ).one()

            assert bool(existing_user.email_verified) is True
            assert existing_user.email_verified_at is None

            # Roll back only the email-verification migration.
            command.downgrade(config, "20261030_01")

            downgraded_inspector = inspect(connection)

            # The original token table and its record must survive downgrade.
            assert (
                "email_verification_tokens"
                in downgraded_inspector.get_table_names()
            )

            preserved_token = connection.exec_driver_sql(
                """
                SELECT id, user_id, token_hash
                FROM email_verification_tokens
                WHERE id = 1
                """
            ).one()

            assert preserved_token.id == 1
            assert preserved_token.user_id == 1
            assert preserved_token.token_hash == existing_token_hash

            # Pre-existing indexes must also survive downgrade.
            preserved_indexes = {
                index["name"]
                for index in downgraded_inspector.get_indexes(
                    "email_verification_tokens"
                )
            }

            assert preserved_indexes == {
                "ix_email_verification_tokens_user_id",
                "ix_email_verification_tokens_user_expiry",
            }

            # The uniqueness constraint must also survive downgrade.
            assert _has_unique_token_hash(connection)

            # Only the email-verification columns should be removed.
            downgraded_user_columns = {
                column["name"]
                for column in downgraded_inspector.get_columns("users")
            }

            assert "email_verified" not in downgraded_user_columns
            assert "email_verified_at" not in downgraded_user_columns

            # The earlier authentication-session migration remains applied.
            assert "auth_sessions" in downgraded_inspector.get_table_names()

            # Complete the remaining downgrade.
            command.downgrade(config, "base")

            final_inspector = inspect(connection)
            final_tables = set(final_inspector.get_table_names())

            assert "auth_sessions" not in final_tables

            # The pre-existing token table is still preserved.
            assert "email_verification_tokens" in final_tables

            final_token_count = connection.exec_driver_sql(
                "SELECT COUNT(*) FROM email_verification_tokens"
            ).scalar_one()

            assert final_token_count == 1

            # The unique token hash constraint must still be present.
            assert _has_unique_token_hash(connection)

    finally:
        test_engine.dispose()


def test_email_verification_migration_rejects_incompatible_token_table(
    tmp_path,
):
    """Reject an incompatible token table without modifying existing data."""
    database = tmp_path / "migration-invalid-token-table.db"
    test_engine = create_engine(f"sqlite:///{database}")

    try:
        with test_engine.begin() as connection:
            # Create the legacy users table.
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

            # Preserve an existing account for the failure-safety check.
            connection.exec_driver_sql(
                """
                INSERT INTO users (
                    id,
                    email,
                    password_hash,
                    created_at
                )
                VALUES (
                    1,
                    'existing@example.com',
                    'existing-password-hash',
                    '2026-01-01 12:00:00'
                )
                """
            )

            config = _config()
            config.attributes["connection"] = connection

            # Apply the preceding migration so only the email-verification
            # migration remains to be tested.
            command.upgrade(config, "20261030_01")

            # Create an incompatible token table.
            # It intentionally lacks the required created_at column.
            connection.exec_driver_sql(
                """
                CREATE TABLE email_verification_tokens (
                    id INTEGER NOT NULL PRIMARY KEY,
                    user_id INTEGER NOT NULL,
                    token_hash VARCHAR(64) NOT NULL UNIQUE,
                    expires_at DATETIME NOT NULL,
                    used_at DATETIME
                )
                """
            )

            original_user_columns = {
                column["name"]
                for column in inspect(connection).get_columns("users")
            }

            original_token_columns = {
                column["name"]
                for column in inspect(connection).get_columns(
                    "email_verification_tokens"
                )
            }

            # The migration must reject the incompatible table.
            with pytest.raises(RuntimeError, match="missing column"):
                command.upgrade(config, "head")

            inspector = inspect(connection)
            table_names = set(inspector.get_table_names())

            # Existing users columns must remain unchanged.
            assert {
                column["name"]
                for column in inspector.get_columns("users")
            } == original_user_columns

            assert "email_verified" not in original_user_columns
            assert "email_verified_at" not in original_user_columns

            # The incompatible token table must remain unchanged.
            assert {
                column["name"]
                for column in inspector.get_columns(
                    "email_verification_tokens"
                )
            } == original_token_columns

            # No migration ownership/state table should be created.
            assert "_migration_20261101_01_state" not in table_names

            # The existing account must remain intact.
            existing_user = connection.exec_driver_sql(
                """
                SELECT email, password_hash
                FROM users
                WHERE id = 1
                """
            ).one()

            assert existing_user.email == "existing@example.com"
            assert existing_user.password_hash == "existing-password-hash"

            # The failed migration must not advance the Alembic revision.
            current_revision = connection.exec_driver_sql(
                "SELECT version_num FROM alembic_version"
            ).scalar_one()

            assert current_revision == "20261030_01"

    finally:
        test_engine.dispose()


def test_migration_rejects_partial_unique_token_hash_index(tmp_path):
    """A partial unique index must not satisfy token-hash uniqueness."""
    database = tmp_path / "partial-unique-token-hash.db"
    test_engine = create_engine(f"sqlite:///{database}")

    try:
        with test_engine.begin() as connection:
            config = _config()
            config.attributes["connection"] = connection

            _prepare_existing_token_table(connection, config)

            # This index enforces uniqueness only for a subset of rows.
            connection.exec_driver_sql(
                """
                CREATE UNIQUE INDEX uq_partial_token_hash
                ON email_verification_tokens (token_hash)
                WHERE token_hash <> ''
                """
            )

            with pytest.raises(RuntimeError):
                command.upgrade(config, "head")

            # The failed migration must not advance the revision.
            current_revision = connection.exec_driver_sql(
                "SELECT version_num FROM alembic_version"
            ).scalar_one()

            assert current_revision == "20261030_01"

            # The migration must not have added its user columns.
            user_columns = {
                column["name"]
                for column in inspect(connection).get_columns("users")
            }

            assert "email_verified" not in user_columns
            assert "email_verified_at" not in user_columns

    finally:
        test_engine.dispose()


def test_migration_does_not_reuse_partial_user_id_index(tmp_path):
    """A differently named partial index must not replace a full index."""
    database = tmp_path / "partial-user-id-index.db"
    test_engine = create_engine(f"sqlite:///{database}")

    try:
        with test_engine.begin() as connection:
            config = _config()
            config.attributes["connection"] = connection

            _prepare_existing_token_table(connection, config)

            # Provide valid full uniqueness for token_hash.
            connection.exec_driver_sql(
                """
                CREATE UNIQUE INDEX uq_email_verification_token_hash
                ON email_verification_tokens (token_hash)
                """
            )

            # This partial index must not satisfy the required user_id index.
            connection.exec_driver_sql(
                """
                CREATE INDEX ix_partial_email_verification_user_id
                ON email_verification_tokens (user_id)
                WHERE user_id > 0
                """
            )

            command.upgrade(config, "head")

            inspector = inspect(connection)
            indexes = {
                index["name"]: index
                for index in inspector.get_indexes(
                    "email_verification_tokens"
                )
            }

            # The migration must create its required full index.
            assert "ix_email_verification_tokens_user_id" in indexes

            required_index = indexes[
                "ix_email_verification_tokens_user_id"
            ]

            assert required_index["column_names"] == ["user_id"]

            # SQLite exposes whether an index is partial through PRAGMA.
            index_rows = connection.exec_driver_sql(
                "PRAGMA index_list('email_verification_tokens')"
            ).fetchall()

            required_index_row = next(
                index
                for index in index_rows
                if index[1] == "ix_email_verification_tokens_user_id"
            )

            assert bool(required_index_row[4]) is False

            # The original partial index should remain untouched.
            assert (
                "ix_partial_email_verification_user_id" in indexes
            )

    finally:
        test_engine.dispose()


def test_migration_rejects_partial_index_using_required_name(tmp_path):
    """A partial index with a required name must not be accepted."""
    database = tmp_path / "partial-required-index-name.db"
    test_engine = create_engine(f"sqlite:///{database}")

    try:
        with test_engine.begin() as connection:
            config = _config()
            config.attributes["connection"] = connection

            _prepare_existing_token_table(connection, config)

            # Provide valid full uniqueness for token_hash.
            connection.exec_driver_sql(
                """
                CREATE UNIQUE INDEX uq_email_verification_token_hash
                ON email_verification_tokens (token_hash)
                """
            )

            # The required name is present, but its index is partial.
            connection.exec_driver_sql(
                """
                CREATE INDEX ix_email_verification_tokens_user_id
                ON email_verification_tokens (user_id)
                WHERE user_id > 0
                """
            )

            with pytest.raises(RuntimeError):
                command.upgrade(config, "head")

            # The migration must fail without advancing its revision.
            current_revision = connection.exec_driver_sql(
                "SELECT version_num FROM alembic_version"
            ).scalar_one()

            assert current_revision == "20261030_01"

            # The incompatible index must not be silently replaced.
            index_rows = connection.exec_driver_sql(
                "PRAGMA index_list('email_verification_tokens')"
            ).fetchall()

            required_index_row = next(
                index
                for index in index_rows
                if index[1] == "ix_email_verification_tokens_user_id"
            )

            assert bool(required_index_row[4]) is True

    finally:
        test_engine.dispose()


def test_customer_email_migration_rejects_existing_duplicates(tmp_path):
    """Reject duplicate normalized emails without advancing the revision."""
    database = tmp_path / "duplicate-customer-emails.db"
    test_engine = create_engine(f"sqlite:///{database}")

    try:
        with test_engine.begin() as connection:
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

            _create_legacy_customers_table(connection)

            config = _config()
            config.attributes["connection"] = connection

            # Apply all revisions before the customer uniqueness migration.
            command.upgrade(config, "20261101_01")

            connection.exec_driver_sql(
                """
                INSERT INTO users (
                    id, email, password_hash, created_at
                )
                VALUES (
                    1, 'owner@example.com', 'test-hash',
                    '2026-01-01 00:00:00'
                )
                """
            )

            connection.exec_driver_sql(
                """
                INSERT INTO customers (
                    id, user_id, name, email
                )
                VALUES
                    (1, 1, 'First Customer',
                     'Contact@example.com'),
                    (2, 1, 'Duplicate Customer',
                     ' contact@EXAMPLE.com ')
                """
            )

            with pytest.raises(
                RuntimeError,
                match="duplicate normalized email",
            ):
                command.upgrade(config, "head")

            current_revision = connection.exec_driver_sql(
                "SELECT version_num FROM alembic_version"
            ).scalar_one()

            assert current_revision == "20261101_01"

            # The failed migration must not leave its expression index behind.
            assert not _customer_email_index_exists(connection)

            customer_count = connection.exec_driver_sql(
                "SELECT COUNT(*) FROM customers"
            ).scalar_one()

            assert customer_count == 2

    finally:
        test_engine.dispose()

def test_password_reset_migration_upgrade_and_downgrade(tmp_path):
    """The password reset table is created at head and removed on downgrade."""
    database = tmp_path / "password-reset-migration.db"
    test_engine = create_engine(f"sqlite:///{database}")

    try:
        with test_engine.begin() as connection:
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
            _create_legacy_customers_table(connection)

            config = _config()
            config.attributes["connection"] = connection
            command.upgrade(config, "head")

            inspector = inspect(connection)
            assert "password_reset_tokens" in inspector.get_table_names()

            columns = {
                column["name"]: column
                for column in inspector.get_columns("password_reset_tokens")
            }
            assert set(columns) == {
                "id", "user_id", "token_hash", "expires_at", "used_at", "created_at",
            }
            assert columns["used_at"]["nullable"] is True
            assert columns["token_hash"]["nullable"] is False

            assert any(
                fk["referred_table"] == "users"
                and fk["constrained_columns"] == ["user_id"]
                and fk["options"].get("ondelete") == "CASCADE"
                for fk in inspector.get_foreign_keys("password_reset_tokens")
            )
            assert {
                index["name"]
                for index in inspector.get_indexes("password_reset_tokens")
            } == {
                "ix_password_reset_tokens_user_id",
                "ix_password_reset_tokens_user_expiry",
            }
            assert any(
                constraint["column_names"] == ["token_hash"]
                for constraint in inspector.get_unique_constraints(
                    "password_reset_tokens"
                )
            )

            # Step back past the reset table (and the worksheet tables after it).
            command.downgrade(config, "20261104_01")
            downgraded = set(inspect(connection).get_table_names())
            assert "password_reset_tokens" not in downgraded
            assert "email_verification_tokens" in downgraded

            # Re-applying works after a downgrade.
            command.upgrade(config, "head")
            assert "password_reset_tokens" in inspect(connection).get_table_names()

    finally:
        test_engine.dispose()


def test_trade_worksheet_migration_upgrade_and_downgrade(tmp_path):
    """Worksheet tables are created at head and removed on downgrade."""
    database = tmp_path / "worksheet-migration.db"
    test_engine = create_engine(f"sqlite:///{database}")

    try:
        with test_engine.begin() as connection:
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
            _create_legacy_customers_table(connection)

            config = _config()
            config.attributes["connection"] = connection
            command.upgrade(config, "head")

            inspector = inspect(connection)
            tables = set(inspector.get_table_names())
            assert {
                "job_worksheets",
                "worksheet_sketches",
                "report_worksheet_snapshots",
            } <= tables

            assert {c["name"] for c in inspector.get_columns("job_worksheets")} == {
                "id", "job_id", "trade", "data", "notes", "created_at", "updated_at",
            }
            assert {c["name"] for c in inspector.get_columns("worksheet_sketches")} == {
                "id", "job_id", "subject", "content_type", "image", "size_bytes",
                "width", "height", "sha256", "created_at",
            }
            for table, column, target in (
                ("job_worksheets", "job_id", "jobs"),
                ("worksheet_sketches", "job_id", "jobs"),
                ("report_worksheet_snapshots", "report_id", "service_reports"),
            ):
                assert any(
                    fk["referred_table"] == target
                    and fk["constrained_columns"] == [column]
                    and fk["options"].get("ondelete") == "CASCADE"
                    for fk in inspector.get_foreign_keys(table)
                ), table
            assert any(
                constraint["column_names"] == ["job_id"]
                for constraint in inspector.get_unique_constraints("job_worksheets")
            )

            command.downgrade(config, "20261118_01")
            remaining = set(inspect(connection).get_table_names())
            assert not {
                "job_worksheets",
                "worksheet_sketches",
                "report_worksheet_snapshots",
            } & remaining
            assert {"jobs", "service_reports", "password_reset_tokens"} <= remaining

            command.upgrade(config, "head")
            assert "job_worksheets" in inspect(connection).get_table_names()

    finally:
        test_engine.dispose()


def test_business_profile_migration_upgrade_and_downgrade(tmp_path):
    """business_profiles is created at head and removed on downgrade."""
    database = tmp_path / "profile-migration.db"
    test_engine = create_engine(f"sqlite:///{database}")

    try:
        with test_engine.begin() as connection:
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
            _create_legacy_customers_table(connection)

            config = _config()
            config.attributes["connection"] = connection
            command.upgrade(config, "head")

            inspector = inspect(connection)
            assert {c["name"] for c in inspector.get_columns("business_profiles")} == {
                "id", "user_id", "business_name", "phone", "email", "address",
                "license_number", "logo", "logo_content_type", "updated_at",
            }
            assert any(
                fk["referred_table"] == "users"
                and fk["options"].get("ondelete") == "CASCADE"
                for fk in inspector.get_foreign_keys("business_profiles")
            )
            assert any(
                uc["column_names"] == ["user_id"]
                for uc in inspector.get_unique_constraints("business_profiles")
            )

            command.downgrade(config, "20261118_02")
            remaining = set(inspect(connection).get_table_names())
            assert "business_profiles" not in remaining
            assert "job_worksheets" in remaining
    finally:
        test_engine.dispose()


def test_empty_database_builds_from_migrations_alone(tmp_path):
    """A brand-new database must reach head with no tables created beforehand.

    Regression test: the first deploy to a fresh hosted database failed
    because the migrations assumed the pre-Alembic core tables already
    existed. Every model table and column must exist after "upgrade head".
    """
    from app.database import Base
    import app.models  # noqa: F401 - register every model with Base.metadata

    database = tmp_path / "fresh.db"
    test_engine = create_engine(f"sqlite:///{database}")

    try:
        with test_engine.begin() as connection:
            config = _config()
            config.attributes["connection"] = connection
            command.upgrade(config, "head")

            inspector = inspect(connection)
            tables = set(inspector.get_table_names())
            for table in Base.metadata.sorted_tables:
                assert table.name in tables, f"missing table {table.name}"
                columns = {c["name"] for c in inspector.get_columns(table.name)}
                expected = {column.name for column in table.columns}
                assert expected <= columns, (
                    f"{table.name} is missing {sorted(expected - columns)}"
                )

            # Downgrading never drops the core tables (it would delete data).
            command.downgrade(config, "base")
            remaining = set(inspect(connection).get_table_names())
            assert {"users", "customers", "jobs", "service_reports", "tasks"} <= remaining
    finally:
        test_engine.dispose()
