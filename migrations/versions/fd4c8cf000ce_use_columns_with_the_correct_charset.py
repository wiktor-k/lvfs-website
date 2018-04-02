"""

Revision ID: fd4c8cf000ce
Revises: f49b79b3ffdd
Create Date: 2018-04-02 11:14:30.784172

"""

# revision identifiers, used by Alembic.
revision = 'fd4c8cf000ce'
down_revision = 'f49b79b3ffdd'

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import mysql

def upgrade():
    op.alter_column('keywords', 'value')
    op.alter_column('search_events', 'value')
    op.alter_column('users', 'password')
    op.alter_column('users', 'display_name')
    op.alter_column('vendors', 'display_name')
    op.alter_column('vendors', 'description')
    op.alter_column('vendors', 'comments')
    op.alter_column('vendors', 'keywords')
    op.alter_column('keywords', 'value')
    op.alter_column('components', 'name')
    op.alter_column('components', 'summary')
    op.alter_column('components', 'description')
    op.alter_column('components', 'release_description')
    op.alter_column('components', 'url_homepage')
    op.alter_column('components', 'developer_name')
    op.alter_column('components', 'screenshot_url')
    op.alter_column('components', 'screenshot_caption')
    op.alter_column('search_events', 'value')

def downgrade():
    pass
