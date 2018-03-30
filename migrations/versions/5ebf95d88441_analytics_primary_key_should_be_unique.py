"""

Revision ID: 5ebf95d88441
Revises: 9d0a1adc8aee
Create Date: 2018-03-30 19:20:34.983454

"""

# revision identifiers, used by Alembic.
revision = '5ebf95d88441'
down_revision = '9d0a1adc8aee'

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import mysql

def upgrade():
    op.drop_index('ix_analytics_datestr', table_name='analytics')
    op.create_index(op.f('ix_analytics_datestr'), 'analytics', ['datestr'], unique=True)

def downgrade():
    op.drop_index(op.f('ix_analytics_datestr'), table_name='analytics')
    op.create_index('ix_analytics_datestr', 'analytics', ['datestr'], unique=False)
