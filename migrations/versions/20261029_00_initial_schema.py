"""Create the core tables that existed before migrations were introduced.

Revision ID: 20261029_00
Revises:

Before Alembic was added (revision 20261030_01), the users, customers, jobs,
service_reports and tasks tables were created directly from the models. Every
later migration assumes they exist, so a brand-new empty database (a fresh
hosted database, for example) could not be built from migrations alone.

This baseline creates those five tables exactly as the models defined them at
that point. A table that already exists is left untouched, so existing
databases are not changed. Downgrading does nothing: dropping these tables
would delete every account and record.
"""
from alembic import op
import sqlalchemy as sa


revision = "20261029_00"
down_revision = None
branch_labels = None
depends_on = None


def _schema() -> str | None:
    """Use the application's PostgreSQL schema; keep SQLite tests schema-free."""
    return "tradedesk" if op.get_bind().dialect.name == "postgresql" else None


def _tables(schema: str | None) -> list[sa.Table]:
    """The pre-migration core tables, in dependency order."""
    metadata = sa.MetaData()

    def ref(table: str) -> str:
        return f"{schema}.{table}.id" if schema else f"{table}.id"

    users = sa.Table(
        "users",
        metadata,
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("email", sa.String(320), nullable=False),
        sa.Column("password_hash", sa.String(255), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Index("ix_users_email", "email", unique=True),
        schema=schema,
    )
    customers = sa.Table(
        "customers",
        metadata,
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column(
            "user_id",
            sa.Integer(),
            sa.ForeignKey(ref("users"), ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("name", sa.String(120), nullable=False),
        sa.Column("phone", sa.String(40), nullable=True),
        sa.Column("email", sa.String(320), nullable=True),
        sa.Column("address", sa.String(300), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Index("ix_customers_user_id", "user_id"),
        schema=schema,
    )
    jobs = sa.Table(
        "jobs",
        metadata,
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column(
            "user_id",
            sa.Integer(),
            sa.ForeignKey(ref("users"), ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column(
            "customer_id",
            sa.Integer(),
            sa.ForeignKey(ref("customers"), ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("title", sa.String(160), nullable=False),
        sa.Column("trade_type", sa.String(80), nullable=False),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column("notes", sa.Text(), nullable=True),
        sa.Column("status", sa.String(30), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Index("ix_jobs_user_id", "user_id"),
        sa.Index("ix_jobs_customer_id", "customer_id"),
        sa.Index(
            "uq_jobs_customer_title_normalized",
            "customer_id",
            sa.text("lower(trim(title))"),
            unique=True,
        ),
        schema=schema,
    )
    service_reports = sa.Table(
        "service_reports",
        metadata,
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column(
            "job_id",
            sa.Integer(),
            sa.ForeignKey(ref("jobs"), ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("original_notes", sa.Text(), nullable=False),
        sa.Column("generated_content", sa.Text(), nullable=False),
        sa.Column("status", sa.String(20), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.Index("ix_service_reports_job_id", "job_id"),
        schema=schema,
    )
    tasks = sa.Table(
        "tasks",
        metadata,
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column(
            "job_id",
            sa.Integer(),
            sa.ForeignKey(ref("jobs"), ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("title", sa.String(200), nullable=False),
        sa.Column("due_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("status", sa.String(20), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Index("ix_tasks_job_id", "job_id"),
        sa.Index(
            "uq_tasks_job_title_normalized",
            "job_id",
            sa.text("lower(trim(title))"),
            unique=True,
        ),
        schema=schema,
    )
    return [users, customers, jobs, service_reports, tasks]


def upgrade() -> None:
    schema = _schema()
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    for table in _tables(schema):
        # Existing databases already have these tables; never touch them.
        if not inspector.has_table(table.name, schema=schema):
            table.create(bind)


def downgrade() -> None:
    # Intentionally empty: dropping the core tables would delete all data.
    pass
