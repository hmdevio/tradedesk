"""Add business profiles printed on PDF reports.

Revision ID: 20261118_03
Revises: 20261118_02

New table only; no existing table or row is changed.
- business_profiles: one per user (business name, contact details, license
  number, optional logo stored as bytes).
"""

from alembic import op
import sqlalchemy as sa


revision = "20261118_03"
down_revision = "20261118_02"
branch_labels = None
depends_on = None


TABLE = "business_profiles"


def _schema():
    """Use the application schema on PostgreSQL."""
    return (
        "tradedesk"
        if op.get_bind().dialect.name == "postgresql"
        else None
    )


def upgrade():
    """Create the business_profiles table."""
    schema = _schema()
    inspector = sa.inspect(op.get_bind())

    if not inspector.has_table("users", schema=schema):
        raise RuntimeError("Required users table does not exist.")
    if inspector.has_table(TABLE, schema=schema):
        raise RuntimeError(
            f"Table {TABLE} already exists. "
            "Inspect it before applying this migration."
        )

    users = f"{schema}.users.id" if schema else "users.id"
    op.create_table(
        TABLE,
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("user_id", sa.Integer(), nullable=False),
        sa.Column("business_name", sa.String(length=120), nullable=False),
        sa.Column("phone", sa.String(length=40), nullable=True),
        sa.Column("email", sa.String(length=320), nullable=True),
        sa.Column("address", sa.String(length=300), nullable=True),
        sa.Column("license_number", sa.String(length=80), nullable=True),
        sa.Column("logo", sa.LargeBinary(), nullable=True),
        sa.Column("logo_content_type", sa.String(length=30), nullable=True),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(
            ["user_id"],
            [users],
            name="fk_business_profiles_user_id_users",
            ondelete="CASCADE",
        ),
        sa.UniqueConstraint("user_id", name="uq_business_profiles_user_id"),
        schema=schema,
    )


def downgrade():
    """Remove the business_profiles table (its data is lost)."""
    schema = _schema()
    if sa.inspect(op.get_bind()).has_table(TABLE, schema=schema):
        op.drop_table(TABLE, schema=schema)
