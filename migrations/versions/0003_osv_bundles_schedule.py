"""OSV provenance, package matching keys and durable scheduling.

Revision ID: 0003
Revises: 0002
"""

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision = "0003"
down_revision = "0002"
branch_labels = depends_on = None
D = sa.JSON().with_variant(postgresql.JSONB(), "postgresql")
IDENTITY = sa.BigInteger().with_variant(sa.Integer(), "sqlite")


def upgrade():
    op.create_table(
        "osv_advisories",
        sa.Column("id", sa.String(128), primary_key=True),
        sa.Column("ecosystem", sa.String(32), nullable=False),
        sa.Column("modified_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("withdrawn_at", sa.DateTime(timezone=True)),
        sa.Column("record_hash", sa.String(64), nullable=False),
        sa.Column("raw_record", D, nullable=False),
    )
    op.create_index("ix_osv_advisories_ecosystem", "osv_advisories", ["ecosystem"])
    op.add_column("affected_packages", sa.Column("advisory_id", sa.String(128), nullable=True))
    # Batch mode also supports the SQLite test backend's FK alteration.
    with op.batch_alter_table("affected_packages") as batch:
        batch.create_foreign_key("fk_affected_advisory", "osv_advisories", ["advisory_id"], ["id"])
        batch.add_column(sa.Column("package_key", sa.String(16)))
        batch.add_column(
            sa.Column(
                "requires_subscription", sa.Boolean(), server_default=sa.false(), nullable=False
            )
        )
        batch.add_column(sa.Column("source_metadata", D, server_default="{}", nullable=False))
        batch.create_index("ix_affected_packages_advisory_id", ["advisory_id"])
        batch.create_index("ix_affected_bundle", ["distro", "release"])
    op.create_table(
        "scheduled_tasks",
        sa.Column("name", sa.String(32), primary_key=True),
        sa.Column("next_run_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_finished_at", sa.DateTime(timezone=True)),
    )
    op.create_table(
        "task_runs",
        sa.Column("id", IDENTITY, primary_key=True, autoincrement=True),
        sa.Column("task", sa.String(32), nullable=False),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("finished_at", sa.DateTime(timezone=True)),
        sa.Column("elapsed_seconds", sa.Float()),
        sa.Column("attempt", sa.Integer(), nullable=False),
        sa.Column("status", sa.String(16), nullable=False),
        sa.Column("result", D, nullable=False),
        sa.Column("error", sa.String(256)),
    )
    op.create_index("ix_task_runs_task", "task_runs", ["task"])


def downgrade():
    op.drop_index("ix_task_runs_task", table_name="task_runs")
    op.drop_table("task_runs")
    op.drop_table("scheduled_tasks")
    with op.batch_alter_table("affected_packages") as batch:
        batch.drop_index("ix_affected_bundle")
        batch.drop_index("ix_affected_packages_advisory_id")
        batch.drop_constraint("fk_affected_advisory", type_="foreignkey")
        for name in ("advisory_id", "package_key", "requires_subscription", "source_metadata"):
            batch.drop_column(name)
    op.drop_index("ix_osv_advisories_ecosystem", table_name="osv_advisories")
    op.drop_table("osv_advisories")
