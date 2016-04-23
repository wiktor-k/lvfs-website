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
        self.qa_group = None
        self.address = None
        self.message = None
        self.is_important = False
    def __repr__(self):
        return "LvfsEventLogItem object %s" % self.message

def _create_eventlog_item(e):
    item = LvfsEventLogItem()
    item.timestamp = e[0]
    item.username = e[1]
    item.qa_group = e[2]
    item.address = e[3]
    item.message = e[4]
    item.is_important = e[5]
    return item

class LvfsDatabaseEventlog(object):

    def __init__(self, db):
        """ Constructor for object """
        self._db = db

    def add(self, msg, username, qa_group, addr, is_important):
        """ Adds an item to the event log """
        assert msg
        assert username
        assert qa_group
        assert addr
        try:
            cur = self._db.cursor()
            cur.execute("INSERT INTO event_log (username, qa_group, addr, message, is_important) "
                        "VALUES (%s, %s, %s, %s, %s);",
                        (username, qa_group, addr, msg, is_important,))
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

    def size_for_qa_group(self, qa_group):
        """ Gets the length of the event log """
        try:
            cur = self._db.cursor()
            cur.execute("SELECT COUNT(timestamp) FROM event_log "
                        "WHERE qa_group = %s", (qa_group,))
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
            cur.execute("SELECT timestamp, username, qa_group, addr, message, is_important "
                        "FROM event_log ORDER BY id DESC LIMIT %s,%s;",
                        (start, length,))
        except mdb.Error, e:
            raise CursorError(cur, e)
        res = cur.fetchall()
        if not res:
            return []
        items = []
        for e in res:
            items.append(_create_eventlog_item(e))
        return items

    def get_items_for_qa_group(self, qa_group, start, length):
        """ Gets the event log items """
        try:
            cur = self._db.cursor()
            cur.execute("SELECT timestamp, username, qa_group, addr, message, is_important "
                        "FROM event_log WHERE qa_group = %s ORDER BY id DESC LIMIT %s,%s;",
                        (qa_group, start, length,))
        except mdb.Error, e:
            raise CursorError(cur, e)
        res = cur.fetchall()
        if not res:
            return []
        items = []
        for e in res:
            items.append(_create_eventlog_item(e))
        return items
