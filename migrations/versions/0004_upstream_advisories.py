"""Upstream product version ranges for scanner layer L2.

Revision ID: 0004
Revises: 0003
"""

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision = "0004"
down_revision = "0003"
branch_labels = depends_on = None
D = sa.JSON().with_variant(postgresql.JSONB(), "postgresql")


def upgrade():
    op.create_table(
        "upstream_advisories",
        sa.Column("id", sa.String(160), primary_key=True),
        sa.Column("product", sa.String(32), nullable=False),
        sa.Column("source", sa.String(32), nullable=False),
        sa.Column("vulnerability_id", sa.String(64)),
        sa.Column("cve_ids", D, nullable=False),
        sa.Column("ranges", D, nullable=False),
        sa.Column("severity", sa.String(16)),
        sa.Column("ref", sa.Text(), nullable=False),
        sa.Column("record_hash", sa.String(64), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_upstream_advisories_product", "upstream_advisories", ["product"])
    op.create_index(
        "ix_upstream_advisories_vulnerability_id", "upstream_advisories", ["vulnerability_id"]
    )


def downgrade():
    op.drop_index("ix_upstream_advisories_vulnerability_id", table_name="upstream_advisories")
    op.drop_index("ix_upstream_advisories_product", table_name="upstream_advisories")
    op.drop_table("upstream_advisories")
