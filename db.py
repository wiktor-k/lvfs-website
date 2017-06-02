#!/usr/bin/python
# -*- coding: utf-8 -*-
#
# Copyright (C) 2015 Richard Hughes <richard@hughsie.com>
# Licensed under the GNU General Public License Version 2

import MySQLdb as mdb
import cgi
from flask import current_app as app

class CursorError(Exception):
    def __init__(self, cur, e):
        self.value = cgi.escape(cur._last_executed) + '&#10145; ' + cgi.escape(str(e))
    def __str__(self):
        return repr(self.value)

class LvfsDatabase(object):

    def __init__(self, environ):
        """ Constructor for object """
        assert environ
        self._db = None
        try:
            self._db = mdb.connect(app.config['DATABASE_HOST'],
                                   app.config['DATABASE_USERNAME'],
                                   app.config['DATABASE_PASSWORD'],
                                   app.config['DATABASE_DB'],
                                   int(app.config['DATABASE_PORT']),
                                   use_unicode=True, charset='utf8')
            self._db.autocommit(True)
        except mdb.Error as e:
            print("Error %d: %s" % (e.args[0], e.args[1]))
        assert self._db

    def __del__(self):
        """ Clean up the database """
        if self._db:
            self._db.close()

    def cursor(self):
        return self._db.cursor()
