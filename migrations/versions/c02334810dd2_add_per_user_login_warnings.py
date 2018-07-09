"""

Revision ID: c02334810dd2
Revises: b797e21e0536
Create Date: 2018-07-09 12:32:45.586789

"""

# revision identifiers, used by Alembic.
revision = 'c02334810dd2'
down_revision = 'b797e21e0536'

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import mysql

def upgrade():
    op.add_column('users', sa.Column('auth_warning', sa.Text(), nullable=True))

def downgrade():
    op.drop_column('users', 'auth_warning')
