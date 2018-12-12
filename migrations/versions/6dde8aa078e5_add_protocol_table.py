"""

Revision ID: 6dde8aa078e5
Revises: 5bcdefe58b44
Create Date: 2018-12-12 12:46:55.097606

"""

# revision identifiers, used by Alembic.
revision = '6dde8aa078e5'
down_revision = '5bcdefe58b44'

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import mysql

from app import db
from app.models import Component, Protocol

def upgrade():
    if 1:
        op.create_table('protocol',
        sa.Column('protocol_id', sa.Integer(), nullable=False),
        sa.Column('value', sa.Text(), nullable=False),
        sa.Column('name', sa.Text(), nullable=True),
        sa.Column('is_signed', sa.Boolean(), nullable=True),
        sa.PrimaryKeyConstraint('protocol_id'),
        sa.UniqueConstraint('protocol_id'),
        mysql_character_set='utf8mb4'
        )
        op.add_column(u'components', sa.Column('protocol_id', sa.Integer(), nullable=True))
        op.create_foreign_key('components_ibfk_2', 'components', 'protocol', ['protocol_id'], ['protocol_id'])

    # add the protocols we understand now
    if 1:
        db.session.add(Protocol(value='unknown',
                                name='Unknown or unsupported custom format',
                                is_signed=False)
        db.session.add(Protocol(value='com.hughski.ColorHug',
                                name='Hughski ColorHug',
                                is_signed=False)
        db.session.add(Protocol(value='org.altusmetrum.AltOS',
                                name='AltOS Update',
                                is_signed=False)
        db.session.add(Protocol(value='com.qualcomm.DFU',
                                name='Qualcomm (Cambridge Silicon Radio) DFU',
                                is_signed=True)
        db.session.add(Protocol(value='com.dell.Dock',
                                name='Dell Salomon Dock',
                                is_signed=False) # FIXME?
        db.session.add(Protocol(value='com.synaptics.MST',
                                name='Synaptics MST',
                                is_signed=False) # FIXME?
        db.session.add(Protocol(value='org.usb.DFU',
                                name='USB Device Firmware Update (DFU 1.0 and 1.1)',
                                is_signed=False)
        db.session.add(Protocol(value='com.st.DfuSe',
                                name='STMicroelectronics DfuSe',
                                is_signed=False)
        db.session.add(Protocol(value='com.8bitdo',
                                name='8bitdo',
                                is_signed=False)
        db.session.add(Protocol(value='com.google.Fastboot',
                                name='Fastboot',
                                is_signed=False) # FIXME, can be...?
        db.session.add(Protocol(value='org.flashrom',
                                name='Flashrom',
                                is_signed=False)
        db.session.add(Protocol(value='org.nvmexpress',
                                name='NVMe',
                                is_signed=False) # FIXME?
        db.session.add(Protocol(value='org.dmtf.Redfish',
                                name='Redfish',
                                is_signed=True)
        db.session.add(Protocol(value='com.realtek.RTS54',
                                name='Realtek RTS54',
                                is_signed=False)
        db.session.add(Protocol(value='com.acme.Test',
                                name='Test protocol DO NOT USE',
                                is_signed=False)
        db.session.add(Protocol(value='com.intel.Thunderbolt',
                                name='Intel Thunderbolt',
                                is_signed=False) # FIXME?
        db.session.add(Protocol(value='org.uefi.UpdateCapsule',
                                name='UEFI UpdateCapsule',
                                is_signed=True)
        db.session.add(Protocol(value='com.logitech.Unifying',
                                name='Logitech Unifying',
                                is_signed=False)
        db.session.add(Protocol(value='com.logitech.UnifyingSecure',
                                name='Logitech Unifying (Signed)',
                                is_signed=True)
        db.session.add(Protocol(value='com.wacom.USB',
                                name='Wacom (USB devices)',
                                is_signed=False) # FIXME?
        db.session.commit()

    # find the IDs for each value
    proto_id_for_value = {}
    for pr in db.session.query(Protocol).all():
        proto_id_for_value[pr.protocol_value] = pr.protocol_id

    # convert the existing components
    for md in db.session.query(Component).all():
        if md.appstream_id.startswith('com.lenovo.'):
            md.protocol_id = proto_id_for_value['org.uefi.UpdateCapsule']
        elif md.appstream_id.startswith('com.hughski.ColorHug.') or \
             md.appstream_id.startswith('com.hughski.ColorHugALS.') or \
             md.appstream_id.startswith('com.hughski.ColorHug2.'):
            md.protocol_id = proto_id_for_value['com.hughski.ColorHug']
        elif md.appstream_id.startswith('com.intel.Thunderbolt.'):
            md.protocol_id = proto_id_for_value['com.intel.Thunderbolt']
        elif md.appstream_id.startswith('com.intel.'):
            md.protocol_id = proto_id_for_value['org.uefi.UpdateCapsule']
        elif md.appstream_id.startswith('com.Quanta.uefi'):
            md.protocol_id = proto_id_for_value['org.uefi.UpdateCapsule']
        elif md.appstream_id.startswith('com.logitech.'):
            md.protocol_id = proto_id_for_value['com.logitech.Unifying']
        elif md.appstream_id.startswith('TI.'):
            md.protocol_id = proto_id_for_value['org.uefi.UpdateCapsule']
        elif md.appstream_id.startswith('org.linaro.'):
            md.protocol_id = proto_id_for_value['org.uefi.UpdateCapsule']
        elif md.appstream_id.startswith('com.fsoft.'):
            md.protocol_id = proto_id_for_value['org.uefi.UpdateCapsule']
        elif md.appstream_id.startswith('com.hp.'):
            md.protocol_id = proto_id_for_value['org.uefi.UpdateCapsule']
        elif md.appstream_id.startswith('com.dell.uefi'):
            md.protocol_id = proto_id_for_value['org.uefi.UpdateCapsule']
        elif md.appstream_id.startswith('com.dell.tbt'):
            md.protocol_id = proto_id_for_value['com.intel.Thunderbolt']
        elif md.appstream_id.startswith('com.akitio.'):
            md.protocol_id = proto_id_for_value['com.intel.Thunderbolt']
        elif md.appstream_id.startswith('com.nitrokey.'):
            md.protocol_id = proto_id_for_value['org.usb.DFU']
        elif md.appstream_id.startswith('com.8bitdo.'):
            md.protocol_id = proto_id_for_value['com.8bitdo']
        elif md.appstream_id.startswith('com.altusmetrum.'):
            md.protocol_id = proto_id_for_value['org.altusmetrum.AltOS']
        elif md.appstream_id.startswith('com.AIAIAI.'):
            md.protocol_id = proto_id_for_value['com.qualcomm.DFU']
        elif md.appstream_id.startswith('com.acme.'):
            md.protocol_id = proto_id_for_value['org.usb.DFU']
        elif md.appstream_id.startswith('fakedevice'):
            md.protocol_id = proto_id_for_value['org.usb.DFU']
        elif md.appstream_id.startswith('com.jabra.'):
            md.protocol_id = proto_id_for_value['org.usb.DFU']
        elif md.appstream_id.startswith('com.dell.mst'):
            md.protocol_id = proto_id_for_value['com.synaptics.MST']
        elif md.appstream_id.startswith('com.dell.salomon'):
            md.protocol_id = proto_id_for_value['com.dell.Dock']
        elif md.appstream_id.startswith('com.dell.wd'):
            md.protocol_id = proto_id_for_value['unknown']
        elif md.appstream_id.startswith('com.tw.supermicro.'):
            md.protocol_id = proto_id_for_value['org.uefi.UpdateCapsule']
        else:
            print('unknown protocol for', md.appstream_id)
    db.session.commit()

def downgrade():
    op.drop_constraint('components_ibfk_2', 'components', type_='foreignkey')
    op.drop_column(u'components', 'protocol_id')
    op.drop_table('protocol')
