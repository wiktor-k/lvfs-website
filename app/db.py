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
        from .models import Setting, User
        setting = self.session.query(Setting).filter(Setting.key == 'db_schema_version').first()
        if not setting:
            print('Setting initial schema version')
            setting = Setting('db_schema_version', str(0))
            self.session.add(setting)

        if int(setting.value) == 36:
            for u in self.session.query(User).all():
                if not u.unused_is_enabled:
                    u.auth_type = None
                    continue
                if u.unused_is_locked:
                    u.auth_type = 'local+locked'
                    continue
                u.auth_type = 'local'
                continue
            setting.value = 37
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
            self.session.add(User(username='sign-test@fwupd.org',
                                  password='5459dbe5e9aa80e077bfa40f3fb2ca8368ed09b4',
                                  auth_type='local',
                                  display_name='Admin User',
                                  vendor_id=vendor.vendor_id,
                                  is_admin=True,
                                  is_qa=True,
                                  is_analyst=True))
            self.session.commit()
        if not self.session.query(User).filter(User.username == 'anonymous').first():
            self.session.add(User(username='anonymous@fwupd.org',
                                  display_name='Anonymous User',
                                  vendor_id=1))
            self.session.commit()

    def drop_db(self):

        # delete all tables
        self.Base.metadata.drop_all(bind=self.engine)
