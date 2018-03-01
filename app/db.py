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
        from .models import Setting, SearchEvent, Event
        from .hash import _addr_hash
        setting = self.session.query(Setting).filter(Setting.key == 'db_schema_version').first()
        if not setting:
            print('Setting initial schema version')
            setting = Setting('db_schema_version', str(0))
            self.session.add(setting)

        if int(setting.value) == 31:
            print('Creating search_events table')
            self.Base.metadata.tables['search_events'].create(bind=self.engine, checkfirst=True)
            setting.value = 32
            self.session.commit()
            return

        if int(setting.value) == 32:
            print('Getting all events')
            events = self.session.query(Event).order_by(Event.timestamp.asc()).all()
            print('Populating search_events table')
            for e in events:
                if e.message.startswith('User search for'):
                    spl = e.message.split('returned')
                    spl2 = spl[1].split(' ')
                    self.session.add(SearchEvent(value=spl[0][17:-2],
                                                 addr=_addr_hash(e.address),
                                                 timestamp=e.timestamp,
                                                 count=int(spl2[1]),
                                                 method=spl2[2]))
            setting.value = 33
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
