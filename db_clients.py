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

        # test client table exists
        try:
            cur = self._db.cursor()
            cur.execute("SELECT * FROM clients LIMIT 1;")
        except mdb.Error, e:
            sql_db = """
                CREATE TABLE clients (
                  id INT NOT NULL AUTO_INCREMENT,
                  timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                  addr VARCHAR(40) DEFAULT NULL,
                  is_firmware TINYINT DEFAULT 0,
                  filename VARCHAR(256) DEFAULT NULL,
                  user_agent VARCHAR(256) DEFAULT NULL,
                  UNIQUE KEY id (id)
                ) CHARSET=utf8;
            """
            cur.execute(sql_db)

    def get_firmware_count_unique(self, kind):
        """ get the number of files we've provided """
        try:
            cur = self._db.cursor()
            cur.execute("SELECT DISTINCT(COUNT(addr)) FROM clients "
                        "WHERE is_firmware = %s", (kind,))
        except mdb.Error, e:
            raise CursorError(cur, e)
        user_cnt = cur.fetchone()[0]
        if not user_cnt:
            return 0
        return user_cnt

    def get_firmware_count_filename(self, filename):
        """ get the number of files we've provided """
        try:
            cur = self._db.cursor()
            cur.execute("SELECT DISTINCT(COUNT(addr)) FROM clients "
                        "WHERE filename = %s", (filename,))
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
                        "GROUP BY user_agent ORDER BY COUNT(*) DESC LIMIT 6;")
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

    def get_metadata_by_month(self, kind):
        data = []
        now = datetime.date.today()
        for i in range(0, 12):
            month_num = now.month - i
            if month_num < 1:
                month_num = 12 - month_num
            try:
                cur = self._db.cursor()
                cur.execute("SELECT COUNT(*) FROM clients "
                            "WHERE is_firmware = %s AND MONTH(timestamp) = %s;",
                            (kind, month_num,))
            except mdb.Error, e:
                raise CursorError(cur, e)
            data.append(int(cur.fetchone()[0]))
        return data
