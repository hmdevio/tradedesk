"""Add email verification state and token storage.

Revision ID: 20261101_01
Revises: 20261030_01
"""
from alembic import op
import sqlalchemy as sa

revision = "20261101_01"
down_revision = "20261030_01"
branch_labels = None
depends_on = None


def _schema():
    return "tradedesk" if op.get_bind().dialect.name == "postgresql" else None


def upgrade():
    schema = _schema()
    op.add_column("users", sa.Column("email_verified", sa.Boolean(), nullable=False, server_default=sa.true()), schema=schema)
    op.add_column("users", sa.Column("email_verified_at", sa.DateTime(timezone=True), nullable=True), schema=schema)
    op.create_table(
        "email_verification_tokens",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("user_id", sa.Integer(), nullable=False),
        sa.Column("token_hash", sa.String(length=64), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("used_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["user_id"], [f"{schema}.users.id" if schema else "users.id"], ondelete="CASCADE"),
        sa.UniqueConstraint("token_hash", name="uq_email_verification_tokens_token_hash"),
        schema=schema,
    )
    op.create_index("ix_email_verification_tokens_user_id", "email_verification_tokens", ["user_id"], schema=schema)
    op.create_index("ix_email_verification_tokens_token_hash", "email_verification_tokens", ["token_hash"], schema=schema)
    op.create_index("ix_email_verification_tokens_user_expiry", "email_verification_tokens", ["user_id", "expires_at"], schema=schema)


def downgrade():
    schema = _schema()
    op.drop_index("ix_email_verification_tokens_user_expiry", table_name="email_verification_tokens", schema=schema)
    op.drop_index("ix_email_verification_tokens_token_hash", table_name="email_verification_tokens", schema=schema)
    op.drop_index("ix_email_verification_tokens_user_id", table_name="email_verification_tokens", schema=schema)
    op.drop_table("email_verification_tokens", schema=schema)
    op.drop_column("users", "email_verified_at", schema=schema)
    op.drop_column("users", "email_verified", schema=schema)
