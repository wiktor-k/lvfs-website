#!/usr/bin/python
# -*- coding: utf-8 -*-
#
# Copyright (C) 2015 Richard Hughes <richard@hughsie.com>
# Licensed under the GNU General Public License Version 2

import MySQLdb as mdb
import cgi

class CursorError(Exception):
    def __init__(self, cur, e):
        self.value = cgi.escape(cur._last_executed) + '&#10145; ' + cgi.escape(str(e))
    def __str__(self):
        return repr(self.value)

class LvfsDatabase(object):

    def __init__(self, environ):
        """ Constructor for object """
        assert environ
        try:
            if 'OPENSHIFT_MYSQL_DB_HOST' in environ:
                self._db = mdb.connect(environ['OPENSHIFT_MYSQL_DB_HOST'],
                                       environ['OPENSHIFT_MYSQL_DB_USERNAME'],
                                       environ['OPENSHIFT_MYSQL_DB_PASSWORD'],
                                       'secure',
                                       int(environ['OPENSHIFT_MYSQL_DB_PORT']),
                                       use_unicode=True, charset='utf8')
            else:
                # mysql -u root -p
                # CREATE DATABASE secure;
                # CREATE USER 'test'@'localhost' IDENTIFIED BY 'test';
                # USE secure;
                # GRANT ALL ON secure.* TO 'test'@'localhost';
                self._db = mdb.connect('localhost', 'test', 'test', 'secure',
                                       use_unicode=True, charset='utf8')
            self._db.autocommit(True)
        except mdb.Error, e:
            print "Error %d: %s" % (e.args[0], e.args[1])

    def __del__(self):
        """ Clean up the database """
        if self._db:
            self._db.close()

    def generate_backup(self, include_clients=False):
        cur = self.cursor()
        cur.execute("SHOW TABLES")
        data = ""
        tables = []
        for table in cur.fetchall():
            tables.append(table[0])

        for table in tables:

            if table == 'clients' and not include_clients:
                continue

            data += "DROP TABLE IF EXISTS `" + str(table) + "`;"
            cur.execute("SHOW CREATE TABLE `" + str(table) + "`;")
            data += "\n" + str(cur.fetchone()[1]) + ";\n\n"

            cur.execute("SELECT * FROM `" + str(table) + "`;")
            for row in cur.fetchall():
                data += "INSERT INTO `" + str(table) + "` VALUES("
                first = True
                for field in row:
                    if not first:
                        data += ', '
                    data += '"' + str(field) + '"'
                    first = False
                data += ");\n"
            data += "\n\n"
        return data

    def cursor(self):
        return self._db.cursor()
