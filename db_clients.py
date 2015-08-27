#!/usr/bin/python
# -*- coding: utf-8 -*-
#
# Copyright (C) 2015 Richard Hughes <richard@hughsie.com>
# Licensed under the GNU General Public License Version 2

import MySQLdb as mdb
import hashlib

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
            cur.execute("SELECT * FROM clients LIMIT 1;")
        except mdb.Error, e:
            sql_db = """
                CREATE TABLE clients (
                  timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
                  addr VARCHAR(40) DEFAULT NULL UNIQUE,
                  cnt INTEGER DEFAULT 1
                ) CHARSET=utf8;
            """
            cur.execute(sql_db)

        # convert from strings to hashes
        cur.execute("SELECT timestamp, addr FROM clients;")
        res = cur.fetchall()
        for l in res:
            if len(l[1]) == 40:
                continue
            cur.execute("UPDATE clients SET addr=%s WHERE timestamp=%s;",
                        (_addr_hash(l[1]), l[0],))

    def get_metadata_download_cnt(self):
        """ get the number of metadata files we've provided """
        try:
            cur = self._db.cursor()
            cur.execute("SELECT COUNT(addr) FROM clients")
        except mdb.Error, e:
            raise CursorError(cur, e)
        user_cnt = cur.fetchone()[0]
        if not user_cnt:
            return 0
        return user_cnt

    def add(self, address):
        """ Adds a client address into the database """
        try:
            cur = self._db.cursor()
            cur.execute("INSERT INTO clients (addr) VALUES (%s) "
                        "ON DUPLICATE KEY UPDATE cnt=cnt+1;", (_addr_hash(address),))
        except mdb.Error, e:
            raise CursorError(cur, e)
