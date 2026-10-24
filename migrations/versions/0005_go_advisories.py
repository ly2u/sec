"""Go vulnerability database rows for scanning Go-compiled programs.

Revision ID: 0005
Revises: 0004
"""

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision = "0005"
down_revision = "0004"
branch_labels = depends_on = None
D = sa.JSON().with_variant(postgresql.JSONB(), "postgresql")


def upgrade():
    op.create_table(
        "go_advisories",
        sa.Column("id", sa.String(340), primary_key=True),
        sa.Column("vuln_id", sa.String(32), nullable=False),
        sa.Column("module", sa.String(300), nullable=False),
        sa.Column("cve_ids", D, nullable=False),
        sa.Column("ranges", D, nullable=False),
        sa.Column("ref", sa.Text(), nullable=False),
        sa.Column("record_hash", sa.String(64), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_go_advisories_vuln_id", "go_advisories", ["vuln_id"])
    op.create_index("ix_go_advisories_module", "go_advisories", ["module"])


def downgrade():
    op.drop_index("ix_go_advisories_module", table_name="go_advisories")
    op.drop_index("ix_go_advisories_vuln_id", table_name="go_advisories")
    op.drop_table("go_advisories")
