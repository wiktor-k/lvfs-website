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

class LvfsDatabaseClients(object):

    def __init__(self, db):
        """ Constructor for object """
        self._db = db

        # test client table exists
        try:
            cur = self._db.cursor()
            cur.execute("SELECT * FROM clients_v2 LIMIT 1;")
        except mdb.Error, e:
            sql_db = """
                CREATE TABLE clients_v2 (
                  timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP UNIQUE,
                  addr VARCHAR(40) DEFAULT NULL,
                  is_firmware TINYINT DEFAULT 0
                ) CHARSET=utf8;
            """
            cur.execute(sql_db)

            # convert data
            cur.execute("SELECT timestamp, addr FROM clients;")
            res = cur.fetchall()
            for l in res:
                print l
                try:
                    cur.execute("INSERT INTO clients_v2 (timestamp, addr) VALUES (%s, %s);", (l[0], l[1],))
                except mdb.Error, e:
                    print "ignoring:", str(e)

    def get_firmware_count_unique(self):
        """ get the number of metadata files we've provided """
        try:
            cur = self._db.cursor()
            cur.execute("SELECT DISTINCT(COUNT(addr)) FROM clients_v2")
        except mdb.Error, e:
            raise CursorError(cur, e)
        user_cnt = cur.fetchone()[0]
        if not user_cnt:
            return 0
        return user_cnt

    def add_metadata(self, address):
        """ Adds a client address into the database """
        try:
            cur = self._db.cursor()
            cur.execute("INSERT INTO clients_v2 (addr, is_firmware) VALUES (%s, 0);", (_addr_hash(address),))
        except mdb.Error, e:
            raise CursorError(cur, e)

    def add_firmware(self, address):
        """ Adds a client address into the database """
        try:
            cur = self._db.cursor()
            cur.execute("INSERT INTO clients_v2 (addr, is_firmware) VALUES (%s, 1);", (_addr_hash(address),))
        except mdb.Error, e:
            raise CursorError(cur, e)

    def _get_stats(self, size, interval, is_firmware):
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
                cur.execute("SELECT COUNT(*) FROM clients_v2 "
                            "WHERE is_firmware = %s AND timestamp >= %s "
                            "AND timestamp <  %s", (is_firmware, start, end,))
            except mdb.Error, e:
                raise CursorError(cur, e)
            data.append(int(cur.fetchone()[0]))
        return data

    def get_metadata_stats(self, size=30, interval=2):
        """ Gets metadata statistics """
        return self._get_stats(size, interval, 0)

    def get_firmware_stats(self, size=30, interval=2):
        """ Gets firmware statistics """
        return self._get_stats(size, interval, 1)

    def get_metadata_by_hour(self):
        data = []
        for i in range(24):
            try:
                cur = self._db.cursor()
                cur.execute("SELECT COUNT(*) FROM clients WHERE HOUR(timestamp) = %s;", (i,))
            except mdb.Error, e:
                raise CursorError(cur, e)
            data.append(int(cur.fetchone()[0]))
        return data
