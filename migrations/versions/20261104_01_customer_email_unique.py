"""Enforce normalized customer email uniqueness per account.

Revision ID: 20261104_01
Revises: 20261101_01

Customer email addresses are unique per user after trimming whitespace
and converting to lowercase. NULL and blank email addresses are excluded.
"""

from alembic import op
import sqlalchemy as sa


revision = "20261104_01"
down_revision = "20261101_01"
branch_labels = None
depends_on = None


INDEX_NAME = "uq_customers_user_email_normalized"
TABLE_NAME = "customers"


def _schema():
    """Use the application schema on PostgreSQL."""
    return (
        "tradedesk"
        if op.get_bind().dialect.name == "postgresql"
        else None
    )


def _index_exists(bind, schema):
    """Check for the index without relying on SQLite expression reflection."""
    if bind.dialect.name == "sqlite":
        return (
            bind.execute(
                sa.text(
                    """
                    SELECT 1
                    FROM sqlite_master
                    WHERE type = 'index'
                      AND tbl_name = :table_name
                      AND name = :index_name
                    """
                ),
                {
                    "table_name": TABLE_NAME,
                    "index_name": INDEX_NAME,
                },
            ).scalar_one_or_none()
            is not None
        )

    inspector = sa.inspect(bind)
    return any(
        index["name"] == INDEX_NAME
        for index in inspector.get_indexes(TABLE_NAME, schema=schema)
    )


def _check_customer_data(schema):
    """Reject existing duplicate normalized emails before indexing."""
    customers = sa.table(
        TABLE_NAME,
        sa.column("user_id", sa.Integer),
        sa.column("email", sa.String),
        schema=schema,
    )

    normalized_email = sa.func.lower(sa.func.trim(customers.c.email))

    duplicates = (
        sa.select(
            customers.c.user_id,
            sa.func.count().label("duplicate_count"),
        )
        .where(
            customers.c.email.is_not(None),
            sa.func.trim(customers.c.email) != "",
        )
        .group_by(
            customers.c.user_id,
            normalized_email,
        )
        .having(sa.func.count() > 1)
    )

    rows = op.get_bind().execute(duplicates).all()

    if rows:
        raise RuntimeError(
            "Cannot create customer email uniqueness index: "
            f"{len(rows)} duplicate normalized email group(s) exist. "
            "Resolve the duplicates before retrying this migration."
        )


def upgrade():
    """Create the per-account normalized email uniqueness index."""
    bind = op.get_bind()
    schema = _schema()
    inspector = sa.inspect(bind)

    if not inspector.has_table(TABLE_NAME, schema=schema):
        raise RuntimeError("Required customers table does not exist.")

    if _index_exists(bind, schema):
        raise RuntimeError(
            f"Index {INDEX_NAME} already exists. "
            "Inspect its definition before applying this migration."
        )

    _check_customer_data(schema)

    op.create_index(
        INDEX_NAME,
        TABLE_NAME,
        [
            "user_id",
            sa.text("lower(trim(email))"),
        ],
        unique=True,
        schema=schema,
        postgresql_where=sa.text(
            "email IS NOT NULL AND trim(email) <> ''"
        ),
        sqlite_where=sa.text(
            "email IS NOT NULL AND trim(email) <> ''"
        ),
    )


def downgrade():
    """Remove only the index introduced by this migration."""
    bind = op.get_bind()
    schema = _schema()
    inspector = sa.inspect(bind)

    if not inspector.has_table(TABLE_NAME, schema=schema):
        return

    if _index_exists(bind, schema):
        op.drop_index(
            INDEX_NAME,
            table_name=TABLE_NAME,
            schema=schema,
        )
