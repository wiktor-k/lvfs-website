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

def _get_datestr_from_datetime(when):
    return int("%04i%02i%02i" % (when.year, when.month, when.day))

class LvfsDownloadKind(object):
    METADATA = 0
    FIRMWARE = 1
    SIGNING = 2

class LvfsDatabaseClients(object):

    def __init__(self, db):
        """ Constructor for object """
        self._db = db

        # test client table exists
        cur = self._db.cursor()
        try:
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

        # test analytics table exists
        try:
            cur.execute("SELECT * FROM analytics LIMIT 1;")
        except mdb.Error, e:
            sql_db = """
                CREATE TABLE analytics (
                  datestr INT DEFAULT 0,
                  kind TINYINT DEFAULT 0,
                  cnt INT DEFAULT 1,
                  UNIQUE (datestr,kind)
                ) CHARSET=utf8;
            """
            cur.execute(sql_db)

    def log(self, when, kind):
        """ get the number of files we've provided """
        datestr = _get_datestr_from_datetime(when)
        try:
            cur = self._db.cursor()
            cur.execute("INSERT INTO analytics (datestr,kind) VALUES (%s, %s) "
                        "ON DUPLICATE KEY UPDATE cnt=cnt+1;",
                        (datestr, kind,))
        except mdb.Error, e:
            raise CursorError(cur, e)

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
                        "WHERE user_agent IS NOT NULL AND is_firmware = %s "
                        "GROUP BY user_agent ORDER BY COUNT(*) DESC LIMIT 6;",
                        (LvfsDownloadKind.FIRMWARE,))
        except mdb.Error, e:
            raise CursorError(cur, e)
        res = cur.fetchall()
        if not res:
            return (["No data"], [0])
        labels = []
        data = []
        for e in res:
            # split up a generic agent to a specific client
            user_agent = e[0]
            sections = user_agent.split(' ')
            if sections[0] == 'Mozilla/5.0':
                if len(sections) >= 3:
                    user_agent = sections[2].replace(';', '')
            labels.append(user_agent)
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

    def get_stats_for_month(self, kind):
        """ Gets stats data for the last month """
        data = []
        now = datetime.date.today()

        cur = self._db.cursor()
        for i in range(30):
            datestr = _get_datestr_from_datetime(now)
            try:
                cur.execute("SELECT cnt FROM analytics "
                            "WHERE kind = %s AND datestr = %s",
                            (kind, datestr,))
            except mdb.Error, e:
                raise CursorError(cur, e)
            res = cur.fetchone()
            if res is None:
                data.append(0)
                continue
            data.append(int(res[0]))

            # back one day
            now -= datetime.timedelta(days=1)
        return data

    def get_stats_for_year(self, kind):
        """ Gets stats data for the last year """
        data = []
        now = datetime.date.today()

        cur = self._db.cursor()
        for i in range(12):
            datestrold = _get_datestr_from_datetime(now)
            now -= datetime.timedelta(days=30)
            datestrnew = _get_datestr_from_datetime(now)
            try:
                cur.execute("SELECT cnt FROM analytics WHERE kind = %s "
                            "AND datestr < %s AND datestr >= %s;",
                            (kind, datestrold, datestrnew,))
            except mdb.Error, e:
                raise CursorError(cur, e)
            res = cur.fetchall()
            if res is None:
                data.append(0)
                continue

            # sum up all the totals for each day in that month
            cnt = 0
            for res2 in res:
                cnt += res2[0]
            data.append(int(cnt))
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
