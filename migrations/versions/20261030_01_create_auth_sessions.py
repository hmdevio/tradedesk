"""Create server-side authentication sessions.

Revision ID: 20261030_01
Revises: 20261029_00
"""
from alembic import op
import sqlalchemy as sa

revision = "20261030_01"
down_revision = "20261029_00"
branch_labels = None
depends_on = None


def _schema() -> str | None:
    """Use the application's PostgreSQL schema; keep SQLite tests schema-free."""
    return "tradedesk" if op.get_bind().dialect.name == "postgresql" else None


def upgrade() -> None:
    schema = _schema()
    user_table = "tradedesk.users.id" if schema else "users.id"

    op.create_table(
        "auth_sessions",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("user_id", sa.Integer(), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(
            ["user_id"],
            [user_table],
            name="fk_auth_sessions_user_id_users",
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id", name="pk_auth_sessions"),
        schema=schema,
    )
    op.create_index(
        "ix_auth_sessions_user_id",
        "auth_sessions",
        ["user_id"],
        unique=False,
        schema=schema,
    )
    op.create_index(
        "ix_auth_sessions_user_expiry",
        "auth_sessions",
        ["user_id", "expires_at"],
        unique=False,
        schema=schema,
    )


def downgrade() -> None:
    schema = _schema()
    op.drop_index(
        "ix_auth_sessions_user_expiry",
        table_name="auth_sessions",
        schema=schema,
    )
    op.drop_index(
        "ix_auth_sessions_user_id",
        table_name="auth_sessions",
        schema=schema,
    )
    op.drop_table("auth_sessions", schema=schema)
