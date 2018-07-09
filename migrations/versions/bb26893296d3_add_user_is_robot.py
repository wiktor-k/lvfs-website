"""

Revision ID: bb26893296d3
Revises: 9ff9005d6cae
Create Date: 2018-07-09 19:41:50.257991

"""

# revision identifiers, used by Alembic.
revision = 'bb26893296d3'
down_revision = '9ff9005d6cae'

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import mysql

def upgrade():
    op.add_column('users', sa.Column('is_robot', sa.Boolean(), nullable=True))

def downgrade():
    op.drop_column('users', 'is_robot')
