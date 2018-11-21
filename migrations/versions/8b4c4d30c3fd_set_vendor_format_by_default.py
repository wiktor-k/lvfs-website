"""

Revision ID: 8b4c4d30c3fd
Revises: 687f5c4d0aa3
Create Date: 2018-11-21 10:35:10.009124

"""

# revision identifiers, used by Alembic.
revision = '8b4c4d30c3fd'
down_revision = '687f5c4d0aa3'

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import mysql

from app import db
from app.models import Component

def upgrade():
    for md in db.session.query(Component).all():
        if md.version_format:
            continue
        if not md.fw.vendor.version_format:
            continue
        if md.version.find('.') != -1:
            continue
        md.version_format = md.fw.vendor.version_format
    db.session.commit()

def downgrade():
    pass
