"""Suppress bootstrap events, retain CVSS provenance and authoritative KEV history.

Revision ID: 0002
Revises: 0001
"""

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision = "0002"
down_revision = "0001"
branch_labels = None
depends_on = None


def upgrade():
    op.add_column(
        "vulnerability_events",
        sa.Column("is_baseline", sa.Boolean(), server_default=sa.true(), nullable=False),
    )
    op.create_index("ix_events_public_time", "vulnerability_events", ["is_baseline", "happened_at"])
    op.add_column(
        "ingestion_state",
        sa.Column("has_completed", sa.Boolean(), server_default=sa.false(), nullable=False),
    )
    op.execute("UPDATE ingestion_state SET has_completed = completed")
    op.alter_column("vulnerabilities", "cisa_kev", new_column_name="adp_kev_flag")
    op.add_column("vulnerabilities", sa.Column("cvss_version", sa.String(8)))
    op.add_column("vulnerabilities", sa.Column("cvss_vector", sa.Text()))
    op.add_column("vulnerabilities", sa.Column("cvss_source", sa.String(32)))
    document = sa.JSON().with_variant(postgresql.JSONB(), "postgresql")
    op.add_column(
        "vulnerabilities",
        sa.Column("cvss_metrics", document, server_default=sa.text("'[]'"), nullable=False),
    )
    op.add_column(
        "kev_entries",
        sa.Column("is_active", sa.Boolean(), server_default=sa.true(), nullable=False),
    )
    op.add_column("kev_entries", sa.Column("removed_at", sa.DateTime(timezone=True)))


def downgrade():
    op.drop_column("kev_entries", "removed_at")
    op.drop_column("kev_entries", "is_active")
    for column in ("cvss_metrics", "cvss_source", "cvss_vector", "cvss_version"):
        op.drop_column("vulnerabilities", column)
    op.alter_column("vulnerabilities", "adp_kev_flag", new_column_name="cisa_kev")
    op.drop_column("ingestion_state", "has_completed")
    op.drop_index("ix_events_public_time", table_name="vulnerability_events")
    op.drop_column("vulnerability_events", "is_baseline")
