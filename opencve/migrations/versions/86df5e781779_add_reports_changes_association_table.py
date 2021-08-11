"""Add reports_changes association table

Revision ID: 86df5e781779
Revises: 734adf2b9084
Create Date: 2021-09-08 00:10:25.526057

"""

# revision identifiers, used by Alembic.
revision = "86df5e781779"
down_revision = "734adf2b9084"

from alembic import op
import sqlalchemy as sa
from sqlalchemy_utils import UUIDType


def upgrade():
    op.create_table(
        "reports_changes",
        sa.Column("report_id", UUIDType(binary=False), nullable=False),
        sa.Column("change_id", UUIDType(binary=False), nullable=False),
        sa.ForeignKeyConstraint(
            ["change_id"],
            ["changes.id"],
        ),
        sa.ForeignKeyConstraint(
            ["report_id"],
            ["reports.id"],
        ),
        sa.PrimaryKeyConstraint("report_id", "change_id"),
    )


def downgrade():
    op.drop_table("reports_changes")
