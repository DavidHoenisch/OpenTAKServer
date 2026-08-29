"""Add CASEVAC HLZ zone fields

Revision ID: 4cd8e08cb7ca
Revises: 640de7aafac2
Create Date: 2026-08-29 14:00:00.000000

"""

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision = "4cd8e08cb7ca"
down_revision = "640de7aafac2"
branch_labels = None
depends_on = None


def upgrade():
    with op.batch_alter_table("casevac", schema=None) as batch_op:
        batch_op.add_column(sa.Column("zone_protected_coord", sa.String(255), nullable=True))
        batch_op.add_column(sa.Column("zone_prot_marker", sa.String(255), nullable=True))


def downgrade():
    with op.batch_alter_table("casevac", schema=None) as batch_op:
        batch_op.drop_column("zone_prot_marker")
        batch_op.drop_column("zone_protected_coord")
