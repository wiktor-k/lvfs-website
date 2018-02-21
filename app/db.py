#!/usr/bin/python
# -*- coding: utf-8 -*-
#
# Copyright (C) 2015-2018 Richard Hughes <richard@hughsie.com>
# Licensed under the GNU General Public License Version 2

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
        from .models import Setting, Component, Firmware, Report, Client
        setting = self.session.query(Setting).filter(Setting.key == 'db_schema_version').first()
        if not setting:
            print('Setting initial schema version')
            setting = Setting('db_schema_version', str(0))
            self.session.add(setting)

        # version 16 adds a primary key on the Firmware table
        if int(setting.value) == 16:
            print('Setting the firmware_id on each component')
            for c in self.session.query(Component).all():
                fw = self.session.query(Firmware).filter(Firmware.checksum_upload == c.unused_checksum_upload).first()
                if not fw:
                    continue
                c.firmware_id = fw.firmware_id
            setting.value = 17
            print('Committing transaction')
            self.session.commit()
            return

        # use the firmware_id on the reports table
        if int(setting.value) == 17:
            print('Setting the firmware_id on each report')
            for c in self.session.query(Report).all():
                fw = self.session.query(Firmware).\
                        filter(Firmware.checksum_upload == c.unused_checksum_upload).first()
                if not fw:
                    continue
                c.firmware_id = fw.firmware_id
            setting.value = 18
            print('Committing transaction')
            self.session.commit()
            return

        # delete any Client objects with no firmware object and use firmware_id
        if int(setting.value) == 18:
            print('Fixing invalid client objects')
            lookup = {}
            for fw in self.session.query(Firmware).all():
                lookup[fw.filename] = fw.firmware_id
            cnt = 0
            limit = 250000
            for c in self.session.query(Client).filter(Client.firmware_id == 0).limit(limit).all():
                cnt += 1
                if cnt >= limit - 1:
                    print('Too many results, try again for the next set!')
                    self.session.commit()
                    return
                if c.unused_filename not in lookup:
                    self.session.delete(c)
                    continue
                c.firmware_id = lookup[c.unused_filename]
            setting.value = 19
            print('Committing transaction')
            self.session.commit()
            return

        print('No schema changes required')

    def init_db(self):

        # ensure all tables exist
        self.Base.metadata.create_all(bind=self.engine)

        # ensure admin user exists
        from .models import User
        if not self.session.query(User).filter(User.username == 'admin').first():
            self.session.add(User(username='admin',
                                  password='5459dbe5e9aa80e077bfa40f3fb2ca8368ed09b4',
                                  display_name='Admin User',
                                  email='sign-test@fwupd.org',
                                  group_id='admin',
                                  is_enabled=True,
                                  is_qa=True,
                                  is_analyst=True))
            self.session.commit()

    def drop_db(self):

        # delete all tables
        self.Base.metadata.drop_all(bind=self.engine)
