
"""Add email verification state and token storage.

Revision ID: 20261101_01
Revises: 20261030_01

Existing tables are validated and reused. A migration state record tracks
which objects this migration owns so downgrade preserves pre-existing objects.
"""

from alembic import op
import sqlalchemy as sa


revision = "20261101_01"
down_revision = "20261030_01"
branch_labels = None
depends_on = None


TOKEN_TABLE = "email_verification_tokens"
STATE_TABLE = "_migration_20261101_01_state"


TOKEN_COLUMNS = {
    "id": (sa.Integer, False),
    "user_id": (sa.Integer, False),
    "token_hash": (sa.String, False),
    "expires_at": (sa.DateTime, False),
    "used_at": (sa.DateTime, True),
    "created_at": (sa.DateTime, False),
}


USER_COLUMNS = {
    "email_verified": (sa.Boolean, False),
    "email_verified_at": (sa.DateTime, True),
}


def _schema():
    """Use the application schema on PostgreSQL."""
    return (
        "tradedesk"
        if op.get_bind().dialect.name == "postgresql"
        else None
    )


def _inspector():
    """Return a fresh inspector after schema changes."""
    return sa.inspect(op.get_bind())


def _validate_user_columns(schema):
    """Validate existing email verification columns, if present."""
    inspector = _inspector()

    if not inspector.has_table("users", schema=schema):
        raise RuntimeError("Required users table does not exist.")

    columns = {
        column["name"]: column
        for column in inspector.get_columns("users", schema=schema)
    }

    for name, (expected_type, nullable) in USER_COLUMNS.items():
        column = columns.get(name)

        if column is None:
            continue

        if not isinstance(column["type"], expected_type):
            raise RuntimeError(
                f"Existing users.{name} column has an unexpected type."
            )

        if column["nullable"] != nullable:
            raise RuntimeError(
                f"Existing users.{name} column has unexpected nullability."
            )


def _validate_token_table(schema):
    """Validate the existing token table before allowing it to be reused."""
    bind = op.get_bind()
    inspector = _inspector()

    if not inspector.has_table(TOKEN_TABLE, schema=schema):
        raise RuntimeError(
            f"Required existing table {TOKEN_TABLE} does not exist."
        )

    columns = {
        column["name"]: column
        for column in inspector.get_columns(TOKEN_TABLE, schema=schema)
    }

    for name, (expected_type, nullable) in TOKEN_COLUMNS.items():
        column = columns.get(name)

        if column is None:
            raise RuntimeError(
                f"Existing {TOKEN_TABLE} table is missing column {name}."
            )

        if not isinstance(column["type"], expected_type):
            raise RuntimeError(
                f"Existing {TOKEN_TABLE}.{name} has an unexpected type."
            )

        if column["nullable"] != nullable:
            raise RuntimeError(
                f"Existing {TOKEN_TABLE}.{name} has unexpected nullability."
            )

        if name == "token_hash" and column["type"].length != 64:
            raise RuntimeError(
                f"Existing {TOKEN_TABLE}.token_hash must have length 64."
            )

    # Verify the primary key.
    primary_key = inspector.get_pk_constraint(
        TOKEN_TABLE,
        schema=schema,
    )

    if primary_key.get("constrained_columns") != ["id"]:
        raise RuntimeError(
            f"Existing {TOKEN_TABLE} table has an unexpected primary key."
        )

    # Verify the user foreign key and cascading deletion behavior.
    foreign_keys = inspector.get_foreign_keys(
        TOKEN_TABLE,
        schema=schema,
    )

    valid_foreign_key = any(
        fk.get("constrained_columns") == ["user_id"]
        and fk.get("referred_table") == "users"
        and fk.get("referred_columns") == ["id"]
        and (fk.get("referred_schema") or None) == (schema or None)
        and (fk.get("options") or {}).get("ondelete", "").upper()
        == "CASCADE"
        for fk in foreign_keys
    )

    if not valid_foreign_key:
        raise RuntimeError(
            f"Existing {TOKEN_TABLE} table has an unexpected user foreign key."
        )

    # Verify global uniqueness of token_hash.
    unique_constraints = inspector.get_unique_constraints(
        TOKEN_TABLE,
        schema=schema,
    )

    indexes = inspector.get_indexes(
        TOKEN_TABLE,
        schema=schema,
    )

    token_hash_is_unique = any(
        constraint.get("column_names") == ["token_hash"]
        for constraint in unique_constraints
    )

    def is_full_column_index(index, expected_columns):
        """Accept only ordinary, non-partial indexes on exact columns."""
        dialect_options = index.get("dialect_options") or {}

        # Do not evaluate SQLAlchemy predicate expressions as booleans.
        # A non-None predicate means the index is partial.
        has_predicate = any(
            dialect_options.get(option) is not None
            for option in (
                "postgresql_where",
                "sqlite_where",
                "mssql_where",
            )
        )

        return (
            index.get("column_names") == expected_columns
            and not has_predicate
            and not index.get("expressions")
        )

    if not token_hash_is_unique:
        token_hash_is_unique = any(
            index.get("unique", False)
            and is_full_column_index(index, ["token_hash"])
            for index in indexes
        )

    # SQLite may expose inline UNIQUE constraints as internal
    # sqlite_autoindex entries instead of ordinary reflected indexes.
    if not token_hash_is_unique and bind.dialect.name == "sqlite":
        quoted_table = bind.dialect.identifier_preparer.quote(TOKEN_TABLE)

        sqlite_indexes = bind.exec_driver_sql(
            f"PRAGMA index_list({quoted_table})"
        ).fetchall()

        for sqlite_index in sqlite_indexes:
            index_name = sqlite_index[1]
            is_unique = bool(sqlite_index[2])
            is_partial = bool(sqlite_index[4])

            if not is_unique or is_partial:
                continue

            quoted_index = (
                bind.dialect.identifier_preparer.quote(index_name)
            )

            index_columns = bind.exec_driver_sql(
                f"PRAGMA index_info({quoted_index})"
            ).fetchall()

            indexed_columns = [
                row[2] for row in index_columns
            ]

            if indexed_columns == ["token_hash"]:
                token_hash_is_unique = True
                break

    if not token_hash_is_unique:
        raise RuntimeError(
            f"Existing {TOKEN_TABLE} table does not enforce unique token hashes."
        )


def _ensure_index(schema, name, columns):
    """Create a required full-column non-unique index when needed."""
    inspector = _inspector()

    indexes = inspector.get_indexes(
        TOKEN_TABLE,
        schema=schema,
    )

    def is_full_column_index(index):
        """Reject partial, expression, and unique indexes."""
        dialect_options = index.get("dialect_options") or {}

        # Do not evaluate SQLAlchemy predicate expressions as booleans.
        # A non-None predicate means the index is partial.
        has_predicate = any(
            dialect_options.get(option) is not None
            for option in (
                "postgresql_where",
                "sqlite_where",
                "mssql_where",
            )
        )

        return (
            index.get("column_names") == columns
            and not index.get("unique", False)
            and not has_predicate
            and not index.get("expressions")
        )

    named_index = next(
        (
            index
            for index in indexes
            if index["name"] == name
        ),
        None,
    )

    if named_index is not None:
        if not is_full_column_index(named_index):
            raise RuntimeError(
                f"Index {name} exists with an unexpected definition."
            )

        return False

    equivalent_index = any(
        is_full_column_index(index)
        for index in indexes
    )

    if equivalent_index:
        return False

    op.create_index(
        name,
        TOKEN_TABLE,
        columns,
        unique=False,
        schema=schema,
    )

    return True


def _state_table(schema):
    """Return the migration ownership tracking table definition."""
    metadata = sa.MetaData()

    return sa.Table(
        STATE_TABLE,
        metadata,
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column(
            "created_token_table",
            sa.Boolean(),
            nullable=False,
        ),
        sa.Column(
            "created_user_id_index",
            sa.Boolean(),
            nullable=False,
        ),
        sa.Column(
            "created_user_expiry_index",
            sa.Boolean(),
            nullable=False,
        ),
        sa.Column(
            "added_email_verified",
            sa.Boolean(),
            nullable=False,
        ),
        sa.Column(
            "added_email_verified_at",
            sa.Boolean(),
            nullable=False,
        ),
        schema=schema,
    )


def upgrade():
    """Add email verification while preserving compatible existing objects."""
    schema = _schema()
    bind = op.get_bind()
    inspector = _inspector()

    # Stop if migration ownership state already exists.
    if inspector.has_table(STATE_TABLE, schema=schema):
        raise RuntimeError(
            "Email verification migration state already exists. "
            "Inspect the database before proceeding."
        )

    # Validate the users table and any existing verification columns.
    _validate_user_columns(schema)

    # Check and validate the token table BEFORE modifying the schema.
    token_table_existed = inspector.has_table(
        TOKEN_TABLE,
        schema=schema,
    )

    if token_table_existed:
        _validate_token_table(schema)

    # Identify which user columns need to be added.
    user_columns = {
        column["name"]
        for column in _inspector().get_columns(
            "users",
            schema=schema,
        )
    }

    added_email_verified = "email_verified" not in user_columns
    added_email_verified_at = "email_verified_at" not in user_columns

    # Add email verification status.
    # Existing accounts receive TRUE for backward compatibility.
    if added_email_verified:
        op.add_column(
            "users",
            sa.Column(
                "email_verified",
                sa.Boolean(),
                nullable=False,
                server_default=sa.true(),
            ),
            schema=schema,
        )

        # PostgreSQL only: remove the temporary database default after
        # existing rows have been populated. New accounts must explicitly
        # set email_verified=False in application code.
        if bind.dialect.name == "postgresql":
            op.alter_column(
                "users",
                "email_verified",
                server_default=None,
                schema=schema,
            )

    # Add the timestamp recording when an account was verified.
    if added_email_verified_at:
        op.add_column(
            "users",
            sa.Column(
                "email_verified_at",
                sa.DateTime(timezone=True),
                nullable=True,
            ),
            schema=schema,
        )

    # Reuse the existing token table if it passed validation.
    if token_table_existed:
        created_token_table = False

    else:
        op.create_table(
            TOKEN_TABLE,
            sa.Column(
                "id",
                sa.Integer(),
                primary_key=True,
            ),
            sa.Column(
                "user_id",
                sa.Integer(),
                nullable=False,
            ),
            sa.Column(
                "token_hash",
                sa.String(length=64),
                nullable=False,
            ),
            sa.Column(
                "expires_at",
                sa.DateTime(timezone=True),
                nullable=False,
            ),
            sa.Column(
                "used_at",
                sa.DateTime(timezone=True),
                nullable=True,
            ),
            sa.Column(
                "created_at",
                sa.DateTime(timezone=True),
                nullable=False,
            ),
            sa.ForeignKeyConstraint(
                ["user_id"],
                [
                    f"{schema}.users.id"
                    if schema
                    else "users.id"
                ],
                ondelete="CASCADE",
            ),
            sa.UniqueConstraint(
                "token_hash",
                name="uq_email_verification_tokens_token_hash",
            ),
            schema=schema,
        )

        created_token_table = True

    # Ensure required indexes exist without duplicating equivalent indexes.
    created_user_id_index = _ensure_index(
        schema,
        "ix_email_verification_tokens_user_id",
        ["user_id"],
    )

    created_user_expiry_index = _ensure_index(
        schema,
        "ix_email_verification_tokens_user_expiry",
        ["user_id", "expires_at"],
    )

    # Record ownership so downgrade never removes pre-existing objects.
    state = _state_table(schema)

    state.create(
        bind,
        checkfirst=False,
    )

    bind.execute(
        state.insert().values(
            id=1,
            created_token_table=created_token_table,
            created_user_id_index=created_user_id_index,
            created_user_expiry_index=created_user_expiry_index,
            added_email_verified=added_email_verified,
            added_email_verified_at=added_email_verified_at,
        )
    )


def downgrade():
    """Remove only database objects created by this migration."""
    schema = _schema()
    bind = op.get_bind()
    inspector = _inspector()

    if not inspector.has_table(STATE_TABLE, schema=schema):
        raise RuntimeError(
            "Email verification migration ownership state is missing. "
            "Downgrade stopped to prevent accidental data loss."
        )

    state = _state_table(schema)

    ownership = bind.execute(
        sa.select(state).where(state.c.id == 1)
    ).mappings().first()

    if ownership is None:
        raise RuntimeError(
            "Email verification migration ownership record is missing. "
            "Downgrade stopped to prevent accidental data loss."
        )

    # Drop the token table only if this migration created it.
    if ownership["created_token_table"]:
        op.drop_table(
            TOKEN_TABLE,
            schema=schema,
        )

    else:
        # Otherwise, remove only indexes created by this migration.
        if ownership["created_user_expiry_index"]:
            op.drop_index(
                "ix_email_verification_tokens_user_expiry",
                table_name=TOKEN_TABLE,
                schema=schema,
            )

        if ownership["created_user_id_index"]:
            op.drop_index(
                "ix_email_verification_tokens_user_id",
                table_name=TOKEN_TABLE,
                schema=schema,
            )

    # Remove only user columns created by this migration.
    if ownership["added_email_verified_at"]:
        op.drop_column(
            "users",
            "email_verified_at",
            schema=schema,
        )

    if ownership["added_email_verified"]:
        op.drop_column(
            "users",
            "email_verified",
            schema=schema,
        )

    # Remove the migration ownership record.
    state.drop(bind)
