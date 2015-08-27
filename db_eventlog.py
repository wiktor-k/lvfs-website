#!/usr/bin/python
# -*- coding: utf-8 -*-
#
# Copyright (C) 2015 Richard Hughes <richard@hughsie.com>
# Licensed under the GNU General Public License Version 2

import MySQLdb as mdb

from db import CursorError

class LvfsEventLogItem(object):
    def __init__(self):
        """ Constructor for object """
        self.timestamp = None
        self.username = None
        self.address = None
        self.message = None
        self.is_important = False
    def __repr__(self):
        return "LvfsEventLogItem object %s" % self.message

class LvfsDatabaseEventlog(object):

    def __init__(self, db):
        """ Constructor for object """
        self._db = db

        # test event log exists
        try:
            cur = self._db.cursor()
            cur.execute("SELECT * FROM event_log LIMIT 1;")
        except mdb.Error, e:
            sql_db = """
                CREATE TABLE event_log (
                  timestamp TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
                  username VARCHAR(40) NOT NULL DEFAULT '',
                  addr VARCHAR(40) DEFAULT NULL,
                  message TEXT DEFAULT NULL,
                  is_important TINYINT DEFAULT 0
                ) CHARSET=utf8;
            """
            cur.execute(sql_db)

    def add(self, msg, username, addr, is_important):
        """ Adds an item to the event log """
        assert msg
        assert username
        assert addr
        try:
            cur = self._db.cursor()
            cur.execute("INSERT INTO event_log (username, addr, message, is_important) "
                        "VALUES (%s, %s, %s, %s);",
                        (username, addr, msg, is_important,))
        except mdb.Error, e:
            raise CursorError(cur, e)

    def size(self):
        """ Gets the length of the event log """
        try:
            cur = self._db.cursor()
            cur.execute("SELECT COUNT(timestamp) FROM event_log")
        except mdb.Error, e:
            raise CursorError(cur, e)
        res = cur.fetchone()[0]
        if not res:
            return 0
        return res

    def get_items(self, start, length):
        """ Gets the event log items """
        try:
            cur = self._db.cursor()
            cur.execute("SELECT timestamp, username, addr, message, is_important "
                        "FROM event_log ORDER BY timestamp DESC LIMIT %s,%s;",
                        (start, length,))
        except mdb.Error, e:
            raise CursorError(cur, e)
        res = cur.fetchall()
        if not res:
            return []
        items = []
        for e in res:
            item = LvfsEventLogItem()
            item.timestamp = e[0]
            item.username = e[1]
            item.address = e[2]
            item.message = e[3]
            item.is_important = e[4]
            items.append(item)
        return items
