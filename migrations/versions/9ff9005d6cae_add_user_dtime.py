"""

Revision ID: 9ff9005d6cae
Revises: c02334810dd2
Create Date: 2018-07-09 19:21:08.910543

"""

# revision identifiers, used by Alembic.
revision = '9ff9005d6cae'
down_revision = 'c02334810dd2'

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import mysql

def upgrade():
    op.add_column('users', sa.Column('dtime', sa.DateTime(), nullable=True))

def downgrade():
    op.drop_column('users', 'dtime')
