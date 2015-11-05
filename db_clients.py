#!/usr/bin/python
# -*- coding: utf-8 -*-
#
# Copyright (C) 2015 Richard Hughes <richard@hughsie.com>
# Licensed under the GNU General Public License Version 2

import MySQLdb as mdb
import hashlib
import datetime

from db import CursorError

def _addr_hash(value):
    """ Generate a salted hash of the IP address """
    salt = 'addr%%%'
    return hashlib.sha1(salt + value).hexdigest()

class LvfsDownloadKind(object):
    METADATA = 0
    FIRMWARE = 1
    SIGNING = 2

class LvfsDatabaseClients(object):

    def __init__(self, db):
        """ Constructor for object """
        self._db = db

        # rename to new (well, old...) name
        try:
            cur = self._db.cursor()
            cur.execute("RENAME TABLE clients_v2 TO clients;")
        except mdb.Error, e:
            pass

        # test client table exists
        try:
            cur = self._db.cursor()
            cur.execute("SELECT * FROM clients LIMIT 1;")
        except mdb.Error, e:
            sql_db = """
                CREATE TABLE clients (
                  timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP UNIQUE,
                  addr VARCHAR(40) DEFAULT NULL,
                  is_firmware TINYINT DEFAULT 0
                  filename VARCHAR(256) DEFAULT NULL,
                  user_agent VARCHAR(256) DEFAULT NULL,
                ) CHARSET=utf8;
            """
            cur.execute(sql_db)

        # FIXME, remove after a few days
        try:
            cur.execute("SELECT filename FROM clients LIMIT 1;")
        except mdb.Error, e:
            sql_db = """
                ALTER TABLE clients ADD filename VARCHAR(256) DEFAULT NULL;
            """
            cur.execute(sql_db)
        try:
            cur.execute("SELECT user_agent FROM clients LIMIT 1;")
        except mdb.Error, e:
            sql_db = """
                ALTER TABLE clients ADD user_agent VARCHAR(256) DEFAULT NULL;
            """
            cur.execute(sql_db)

    def get_firmware_count_unique(self):
        """ get the number of metadata files we've provided """
        try:
            cur = self._db.cursor()
            cur.execute("SELECT DISTINCT(COUNT(addr)) FROM clients")
        except mdb.Error, e:
            raise CursorError(cur, e)
        user_cnt = cur.fetchone()[0]
        if not user_cnt:
            return 0
        return user_cnt

    def get_user_agent_stats(self):
        """ Gets the number of user agents """
        try:
            cur = self._db.cursor()
            cur.execute("SELECT user_agent, COUNT(*) AS count FROM clients "
                        "WHERE user_agent IS NOT NULL AND filename = 'firmware.xml.gz.asc' "
                        "GROUP BY user_agent;")
        except mdb.Error, e:
            raise CursorError(cur, e)
        res = cur.fetchall()
        if not res:
            return (["No data"],[0])
        labels = []
        data = []
        for e in res:
            labels.append(e[0])
            data.append(e[1])
        return (labels, data)

    def increment(self, address, kind, fn=None, user_agent=None):
        """ Adds a client address into the database """
        try:
            cur = self._db.cursor()
            cur.execute("INSERT INTO clients (addr, is_firmware, filename, user_agent) "
                        "VALUES (%s, %s, %s, %s);",
                        (_addr_hash(address), kind, fn, user_agent,))
        except mdb.Error, e:
            raise CursorError(cur, e)

    def get_stats(self, size, interval, kind):
        """ Gets stats data """
        data = []
        now = datetime.date.today()

        # yes, there's probably a way to do this in one query with a
        # 30-level INNER JOIN or something clever...
        for i in range(size):
            start = now - datetime.timedelta((i * interval) + interval - 1)
            end = now - datetime.timedelta((i * interval) - 1)
            try:
                cur = self._db.cursor()
                cur.execute("SELECT COUNT(*) FROM clients "
                            "WHERE is_firmware = %s AND timestamp >= %s "
                            "AND timestamp <  %s", (kind, start, end,))
            except mdb.Error, e:
                raise CursorError(cur, e)
            data.append(int(cur.fetchone()[0]))
        return data

    def get_stats_for_fn(self, size, interval, filename):
        """ Gets stats data """
        data = []
        now = datetime.date.today()

        # yes, there's probably a way to do this in one query with a
        # 30-level INNER JOIN or something clever...
        for i in range(size):
            start = now - datetime.timedelta((i * interval) + interval - 1)
            end = now - datetime.timedelta((i * interval) - 1)
            try:
                cur = self._db.cursor()
                cur.execute("SELECT COUNT(*) FROM clients "
                            "WHERE filename = %s AND timestamp >= %s "
                            "AND timestamp <  %s", (filename, start, end,))
            except mdb.Error, e:
                raise CursorError(cur, e)
            data.append(int(cur.fetchone()[0]))
        return data

    def get_metadata_by_hour(self):
        data = []
        for i in range(24):
            try:
                cur = self._db.cursor()
                cur.execute("SELECT COUNT(*) FROM clients "
                            "WHERE HOUR(timestamp) = %s;", (i,))
            except mdb.Error, e:
                raise CursorError(cur, e)
            data.append(int(cur.fetchone()[0]))
        return data
