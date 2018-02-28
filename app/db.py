#!/usr/bin/python
# -*- coding: utf-8 -*-
#
# Copyright (C) 2015-2018 Richard Hughes <richard@hughsie.com>
# Licensed under the GNU General Public License Version 2
#
# pylint: disable=too-many-locals,too-many-statements

from __future__ import print_function

from sqlalchemy import create_engine, func
from sqlalchemy.orm import scoped_session, sessionmaker
from sqlalchemy.ext.declarative import declarative_base

def _execute_count_star(q):
    count_query = q.statement.with_only_columns([func.count()]).order_by(None)
    return q.session.execute(count_query).scalar()

class Database(object):

    def __init__(self):
        self.engine = None
        self.session = None
        self.Base = None

    def init_app(self, app):

        # create the engine now the app is loaded
        self.engine = create_engine(app.config['DATABASE'], convert_unicode=True)
        self.engine.echo = app.testing
        self.session = scoped_session(sessionmaker(autocommit=False,
                                                   autoflush=False,
                                                   bind=self.engine))
        self.Base = declarative_base()
        self.Base.query = self.session.query_property()

    def modify_db(self):

        # get current schema version
        from .models import Setting, Event, FirmwareEvent, Firmware, User, Vendor, Issue, Group, Restriction
        setting = self.session.query(Setting).filter(Setting.key == 'db_schema_version').first()
        if not setting:
            print('Setting initial schema version')
            setting = Setting('db_schema_version', str(0))
            self.session.add(setting)

        if int(setting.value) == 20:
            print('Creating firmware_events table')
            self.Base.metadata.tables['firmware_events'].create(bind=self.engine, checkfirst=True)
            setting.value = 21
            self.session.commit()
            return

        if int(setting.value) == 21:
            print('Getting all Firmwares')
            fws_checksum = {}
            fws_filename = {}
            for fw in self.session.query(Firmware).all():
                fws_checksum[fw.checksum_upload] = fw
                fws_filename[fw.filename] = fw
            print('Getting all Users')
            users = {}
            for user in self.session.query(User).all():
                users[user.username] = user
            print('Getting all Events')
            events = self.session.query(Event).order_by(Event.timestamp.asc()).all()
            print('Migrating content to events')
            for e in events:
                if e.message.startswith('Uploaded file'):
                    spl = e.message.split(' ')
                    if len(spl) != 5:
                        continue
                    filename = spl[2]
                    if filename not in fws_filename:
                        print('filename %s does not exist, skipping' % filename)
                        continue
                    if e.username not in users:
                        if e.username == 'dell':
                            user_id = users['dellqa'].user_id
                        else:
                            print('user %s does not exist, using admin' % e.username)
                            user_id = users['admin'].user_id
                    else:
                        user_id = users[e.username].user_id
                    fws_filename[filename].events.append(FirmwareEvent(spl[4], user_id, e.timestamp))

                elif e.message.startswith('Moved firmware'):
                    spl = e.message.split(' ')
                    if len(spl) != 5:
                        continue
                    checksum = spl[2]
                    if checksum not in fws_checksum:
                        print('firmware %s does not exist, skipping' % checksum)
                        continue
                    user_id = users[e.username].user_id
                    fws_checksum[checksum].events.append(FirmwareEvent(spl[4], user_id, e.timestamp))
            setting.value = 22
            self.session.commit()
            return

        if int(setting.value) == 22:
            print('Creating Keyword table')
            self.Base.metadata.tables['keywords'].create(bind=self.engine, checkfirst=True)
            setting.value = 23
            self.session.commit()
            return
        if int(setting.value) == 23:
            print('Creating Keyword table')
            for fw in self.session.query(Firmware).all():
                for md in fw.mds:
                    if md.developer_name:
                        md.add_keywords_from_string(md.developer_name, priority=10)
                    if md.name:
                        md.add_keywords_from_string(md.name, priority=3)
                    if md.summary:
                        md.add_keywords_from_string(md.summary, priority=1)
            setting.value = 24
            print('Committing transaction')
            self.session.commit()
            return

        if int(setting.value) == 24:
            vendors = {}
            for v in self.session.query(Vendor).all():
                vendors[v.group_id] = v
            # create a fake acme vendor
            if 'admin' not in vendors:
                v = Vendor('admin')
                v.display_name = 'Acme Corp.'
                v.description = 'A fake vendor used for testing firmware'
                self.session.add(v)
                self.session.commit()
            setting.value += str(int(setting.value) + 1)
            print('Committing transaction')
            self.session.commit()
            return

        if int(setting.value) == 25:
            vendors = {}
            for v in self.session.query(Vendor).all():
                vendors[v.group_id] = v

            print('Setting the vendor ID on the firmware objects')
            for fw in self.session.query(Firmware).all():
                if fw.unused_group_id in vendors:
                    group_id = fw.unused_group_id
                else:
                    appstream_id = fw.mds[0].appstream_id
                    if appstream_id.startswith('com.hughski.'):
                        group_id = 'hughski'
                    elif appstream_id.startswith('com.8bitdo.'):
                        group_id = '8bitdo'
                    elif appstream_id.startswith('com.altusmetrum.'):
                        group_id = 'altusmetrum'
                    elif appstream_id.startswith('com.AIAIAI.'):
                        group_id = 'aiaiai'
                    elif appstream_id.startswith('com.acme.'):
                        group_id = 'admin'
                    elif appstream_id.startswith('fakedevice'):
                        group_id = 'admin'
                    else:
                        print('MISSING VENDOR %s for %s (%s)' % (fw.unused_group_id, fw.filename, appstream_id))
                        continue
                fw.vendor_id = vendors[group_id].vendor_id
            setting.value += str(int(setting.value) + 1)
            print('Committing transaction')
            self.session.commit()
            return

        if int(setting.value) == 26:
            vendors = {}
            for v in self.session.query(Vendor).all():
                vendors[v.group_id] = v
            print('Setting the vendor ID on the user objects')
            for user in self.session.query(User).all():
                if user.unused_group_id == 'admin':
                    user.vendor_id = vendors['admin'].vendor_id
                    user.is_admin = True
                elif user.unused_group_id in vendors:
                    user.vendor_id = vendors[user.unused_group_id].vendor_id
                else:
                    print('MISSING VENDOR %s for %s' % (user.unused_group_id, user.username))
                    user.vendor_id = vendors['admin'].vendor_id
            setting.value += str(int(setting.value) + 1)
            print('Committing transaction')
            self.session.commit()
            return

        if int(setting.value) == 27:
            vendors = {}
            for v in self.session.query(Vendor).all():
                vendors[v.group_id] = v
            print('Setting the vendor ID on the Event objects')
            for ev in self.session.query(Event).all():
                if not ev.unused_group_id or ev.unused_group_id == 'guest':
                    ev.vendor_id = vendors['admin'].vendor_id
                elif ev.unused_group_id in vendors:
                    ev.vendor_id = vendors[ev.unused_group_id].vendor_id
                else:
                    print('MISSING VENDOR %s for %s' % (ev.unused_group_id, ev.username))
                    ev.vendor_id = vendors['admin'].vendor_id
            setting.value += str(int(setting.value) + 1)
            print('Committing transaction')
            self.session.commit()
            return

        if int(setting.value) == 28:
            vendors = {}
            for v in self.session.query(Vendor).all():
                vendors[v.group_id] = v
            print('Setting the vendor ID on the Issue objects')
            for issue in self.session.query(Issue).all():
                if not issue.unused_group_id:
                    issue.vendor_id = vendors['admin'].vendor_id
                elif issue.unused_group_id in vendors:
                    issue.vendor_id = vendors[issue.unused_group_id].vendor_id
                else:
                    print('MISSING VENDOR %s for %s' % (issue.unused_group_id, issue.url))
                    issue.vendor_id = vendors['admin'].vendor_id
            setting.value += str(int(setting.value) + 1)
            print('Committing transaction')
            self.session.commit()
            return
        if int(setting.value) == 29:
            print('Creating Restriction table')
            self.Base.metadata.tables['restrictions'].create(bind=self.engine, checkfirst=True)
            setting.value += str(int(setting.value) + 1)
            self.session.commit()
            return
        if int(setting.value) == 30:
            vendors = {}
            for v in self.session.query(Vendor).all():
                vendors[v.group_id] = v
            print('Populating Restriction table')
            for group in self.session.query(Group).all():
                v = vendors[group.group_id]
                for vendor_id in group.vendor_ids:
                    v.restrictions.append(Restriction(vendor_id))
            setting.value += str(int(setting.value) + 1)
            print('Committing transaction')
            self.session.commit()
            return

        print('No schema changes required')

    def init_db(self):

        # ensure all tables exist
        self.Base.metadata.create_all(bind=self.engine)

        # ensure admin user exists
        from .models import User, Vendor
        if not self.session.query(User).filter(User.username == 'admin').first():
            vendor = Vendor('admin')
            vendor.display_name = 'Acme Corp.'
            vendor.description = 'A fake vendor used for testing firmware'
            self.session.add(vendor)
            self.session.commit()
            self.session.add(User(username='admin',
                                  password='5459dbe5e9aa80e077bfa40f3fb2ca8368ed09b4',
                                  display_name='Admin User',
                                  email='sign-test@fwupd.org',
                                  vendor_id=vendor.vendor_id,
                                  is_admin=True,
                                  is_enabled=True,
                                  is_qa=True,
                                  is_analyst=True))
            self.session.commit()

    def drop_db(self):

        # delete all tables
        self.Base.metadata.drop_all(bind=self.engine)
