"""Add trade worksheets, worksheet sketches and report worksheet snapshots.

Revision ID: 20261118_02
Revises: 20261118_01

New tables only; no existing table or row is changed.
- job_worksheets: one trade worksheet per job (JSON field values + notes).
- worksheet_sketches: sketch or plot images attached to a job, each with a
  subject line. Images are stored in the database (bytea on PostgreSQL), so
  they are included in normal database backups.
- report_worksheet_snapshots: the worksheet copied at report approval, so an
  approved PDF cannot change afterwards.
"""

from alembic import op
import sqlalchemy as sa


revision = "20261118_02"
down_revision = "20261118_01"
branch_labels = None
depends_on = None


WORKSHEETS = "job_worksheets"
SKETCHES = "worksheet_sketches"
SNAPSHOTS = "report_worksheet_snapshots"
SKETCH_JOB_INDEX = "ix_worksheet_sketches_job_id"


def _schema():
    """Use the application schema on PostgreSQL."""
    return (
        "tradedesk"
        if op.get_bind().dialect.name == "postgresql"
        else None
    )


def _ref(schema, table):
    return f"{schema}.{table}.id" if schema else f"{table}.id"


def upgrade():
    """Create the three worksheet tables."""
    schema = _schema()
    inspector = sa.inspect(op.get_bind())

    for required in ("jobs", "service_reports"):
        if not inspector.has_table(required, schema=schema):
            raise RuntimeError(f"Required {required} table does not exist.")

    for table in (WORKSHEETS, SKETCHES, SNAPSHOTS):
        if inspector.has_table(table, schema=schema):
            raise RuntimeError(
                f"Table {table} already exists. "
                "Inspect it before applying this migration."
            )

    op.create_table(
        WORKSHEETS,
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("job_id", sa.Integer(), nullable=False),
        sa.Column("trade", sa.String(length=40), nullable=False),
        sa.Column("data", sa.Text(), nullable=False),
        sa.Column("notes", sa.Text(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(
            ["job_id"],
            [_ref(schema, "jobs")],
            name="fk_job_worksheets_job_id_jobs",
            ondelete="CASCADE",
        ),
        sa.UniqueConstraint("job_id", name="uq_job_worksheets_job_id"),
        schema=schema,
    )

    op.create_table(
        SKETCHES,
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("job_id", sa.Integer(), nullable=False),
        sa.Column("subject", sa.String(length=120), nullable=False),
        sa.Column("content_type", sa.String(length=30), nullable=False),
        sa.Column("image", sa.LargeBinary(), nullable=False),
        sa.Column("size_bytes", sa.Integer(), nullable=False),
        sa.Column("width", sa.Integer(), nullable=False),
        sa.Column("height", sa.Integer(), nullable=False),
        sa.Column("sha256", sa.String(length=64), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(
            ["job_id"],
            [_ref(schema, "jobs")],
            name="fk_worksheet_sketches_job_id_jobs",
            ondelete="CASCADE",
        ),
        schema=schema,
    )
    op.create_index(
        SKETCH_JOB_INDEX, SKETCHES, ["job_id"], unique=False, schema=schema
    )

    op.create_table(
        SNAPSHOTS,
        sa.Column("report_id", sa.Integer(), primary_key=True),
        sa.Column("content", sa.Text(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(
            ["report_id"],
            [_ref(schema, "service_reports")],
            name="fk_report_worksheet_snapshots_report_id_service_reports",
            ondelete="CASCADE",
        ),
        schema=schema,
    )


def downgrade():
    """Remove the worksheet tables (their data is lost)."""
    schema = _schema()
    inspector = sa.inspect(op.get_bind())

    if inspector.has_table(SNAPSHOTS, schema=schema):
        op.drop_table(SNAPSHOTS, schema=schema)
    if inspector.has_table(SKETCHES, schema=schema):
        op.drop_index(SKETCH_JOB_INDEX, table_name=SKETCHES, schema=schema)
        op.drop_table(SKETCHES, schema=schema)
    if inspector.has_table(WORKSHEETS, schema=schema):
        op.drop_table(WORKSHEETS, schema=schema)
