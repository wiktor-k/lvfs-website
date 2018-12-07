"""

Revision ID: 055858fa038f
Revises: 5bcdefe58b44
Create Date: 2018-12-07 11:29:23.899543

"""

# revision identifiers, used by Alembic.
revision = '055858fa038f'
down_revision = '5bcdefe58b44'

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import mysql

def upgrade():
    op.add_column('vendors', sa.Column('banned_country_codes', sa.Text(), nullable=True))

def downgrade():
    op.drop_column('vendors', 'banned_country_codes')
