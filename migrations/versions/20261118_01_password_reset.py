"""Add password reset token storage.

Revision ID: 20261118_01
Revises: 20261104_01

Reset tokens are high-entropy, single-use, expiring, and stored only as
SHA-256 digests. The table must not already exist.
"""

from alembic import op
import sqlalchemy as sa


revision = "20261118_01"
down_revision = "20261104_01"
branch_labels = None
depends_on = None


TABLE_NAME = "password_reset_tokens"
USER_ID_INDEX = "ix_password_reset_tokens_user_id"
USER_EXPIRY_INDEX = "ix_password_reset_tokens_user_expiry"


def _schema():
    """Use the application schema on PostgreSQL."""
    return (
        "tradedesk"
        if op.get_bind().dialect.name == "postgresql"
        else None
    )


def upgrade():
    """Create the password reset token table and its indexes."""
    schema = _schema()
    inspector = sa.inspect(op.get_bind())

    if not inspector.has_table("users", schema=schema):
        raise RuntimeError("Required users table does not exist.")

    if inspector.has_table(TABLE_NAME, schema=schema):
        raise RuntimeError(
            f"Table {TABLE_NAME} already exists. "
            "Inspect it before applying this migration."
        )

    op.create_table(
        TABLE_NAME,
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("user_id", sa.Integer(), nullable=False),
        sa.Column("token_hash", sa.String(length=64), nullable=False),
        sa.Column(
            "expires_at", sa.DateTime(timezone=True), nullable=False
        ),
        sa.Column("used_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), nullable=False
        ),
        sa.ForeignKeyConstraint(
            ["user_id"],
            [f"{schema}.users.id" if schema else "users.id"],
            name="fk_password_reset_tokens_user_id_users",
            ondelete="CASCADE",
        ),
        sa.UniqueConstraint(
            "token_hash",
            name="uq_password_reset_tokens_token_hash",
        ),
        schema=schema,
    )

    op.create_index(
        USER_ID_INDEX,
        TABLE_NAME,
        ["user_id"],
        unique=False,
        schema=schema,
    )

    op.create_index(
        USER_EXPIRY_INDEX,
        TABLE_NAME,
        ["user_id", "expires_at"],
        unique=False,
        schema=schema,
    )


def downgrade():
    """Remove the password reset token table."""
    schema = _schema()
    inspector = sa.inspect(op.get_bind())

    if not inspector.has_table(TABLE_NAME, schema=schema):
        return

    op.drop_index(USER_EXPIRY_INDEX, table_name=TABLE_NAME, schema=schema)
    op.drop_index(USER_ID_INDEX, table_name=TABLE_NAME, schema=schema)
    op.drop_table(TABLE_NAME, schema=schema)
