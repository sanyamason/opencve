"""Move reviewed from events to changes table

Revision ID: 734adf2b9084
Revises: 85cf2cf2b22a
Create Date: 2021-09-02 16:33:50.607597

"""

# revision identifiers, used by Alembic.
revision = "734adf2b9084"
down_revision = "85cf2cf2b22a"

from alembic import op
import sqlalchemy as sa


def upgrade():
    """
    The changes table can be populated in existing installation of OpenCVE. To avoid
    a `NotNullViolation` error we have to create a nullable field, set all the values
    as True, then alter the field to mark it as not-nullable.
    """
    op.add_column("changes", sa.Column("reviewed", sa.Boolean(), nullable=True))
    op.execute("UPDATE changes SET reviewed = true;")
    op.alter_column("changes", "reviewed", nullable=False)
    op.drop_column("events", "review")


def downgrade():
    op.add_column(
        "events", sa.Column("review", sa.BOOLEAN(), autoincrement=False, nullable=True)
    )
    op.execute("UPDATE events SET review = true;")
    op.drop_column("changes", "reviewed")
