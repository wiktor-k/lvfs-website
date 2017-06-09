#!/usr/bin/python
# -*- coding: utf-8 -*-
#
# Copyright (C) 2015 Richard Hughes <richard@hughsie.com>
# Licensed under the GNU General Public License Version 2

import cgi
import hashlib
import datetime
import MySQLdb as mdb

from .models import User, FirmwareMd, Firmware, EventLogItem, Group
from .hash import _addr_hash, _password_hash

def _create_user_item(e):
    """ Create a user object from the results """
    item = User()
    item.username = e[0]
    item.display_name = e[1]
    item.email = e[2]
    item.password = e[3]
    item.is_enabled = bool(e[4])
    item.is_qa = bool(e[5])
    item.qa_group = e[6]
    item.is_locked = bool(e[7])
    item.pubkey = e[8]
    if item.username == 'admin':
        item.is_enabled = True
        item.is_qa = True
        item.is_locked = False
    return item

def _create_firmware_md(e):
    md = FirmwareMd()
    md.fwid = e[0]
    md.cid = e[1]
    md.guids = e[2].split(',')
    md.version = e[3]
    md.name = e[4]
    md.summary = e[5]
    md.checksum_contents = e[6]
    md.release_description = e[7]
    md.release_timestamp = e[8]
    md.developer_name = e[9]
    md.metadata_license = e[10]
    md.project_license = e[11]
    md.url_homepage = e[12]
    md.description = e[13]
    md.checksum_container = e[14]
    md.filename_contents = e[15]
    md.release_installed_size = e[16]
    md.release_download_size = e[17]
    md.release_urgency = e[18]
    md.screenshot_url = e[19]
    md.screenshot_caption = e[20]
    md.metainfo_id = e[21]
    return md

def _create_firmware_item(e):
    item = Firmware()
    item.qa_group = e[0]
    item.addr = e[1]
    item.timestamp = e[2]
    item.filename = e[3]
    item.fwid = e[4]
    item.target = e[5]
    item.version_display = e[6]
    return item

def _create_eventlog_item(e):
    item = EventLogItem()
    item.timestamp = e[0]
    item.username = e[1]
    item.qa_group = e[2]
    item.address = e[3]
    item.message = e[4]
    item.is_important = e[5]
    return item

def _create_group_id(e):
    item = Group()
    item.group_id = e[0]
    if e[1]:
        item.vendor_ids = e[1].split(',')
    return item

def _get_datestr_from_datetime(when):
    return int("%04i%02i%02i" % (when.year, when.month, when.day))

class CursorError(Exception):
    def __init__(self, cur, e):
        self.value = cgi.escape(cur._last_executed) + '&#10145; ' + cgi.escape(str(e))
    def __str__(self):
        return repr(self.value)

class Database(object):

    def __init__(self, app):
        """ Constructor for object """
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
            print "Error %d: %s" % (e.args[0], e.args[1])
        assert self._db
        self.users = DatabaseUsers(self._db)
        self.groups = DatabaseGroups(self._db)
        self.eventlog = DatabaseEventlog(self._db)
        self.clients = DatabaseClients(self._db)
        self.firmware = DatabaseFirmware(self._db)

    def verify(self):
        """ repairs database when required """
        try:
            cur = self._db.cursor()
            cur.execute("SELECT vendor_ids FROM groups LIMIT 1;")
        except mdb.Error as e:
            cur.execute("""
                        CREATE TABLE groups (
                          group_id VARCHAR(40) NOT NULL DEFAULT '',
                          vendor_ids VARCHAR(40) NOT NULL DEFAULT '',
                          UNIQUE KEY id (group_id)
                        ) CHARSET=utf8;""");
            for user in self.users.get_all():
                if not self.groups.get_item(user.qa_group):
                    self.groups.add(user.qa_group)

    def __del__(self):
        """ Clean up the database """
        if self._db:
            self._db.close()

    def cursor(self):
        return self._db.cursor()

class DatabaseGroups(object):

    def __init__(self, db):
        """ Constructor for object """
        self._db = db

    def add(self, group_id, vendor_ids=''):
        """ Adds the user to the userlist """
        assert group_id
        try:
            cur = self._db.cursor()
            cur.execute("INSERT INTO groups (group_id, vendor_ids) "
                        "VALUES (%s, %s);",
                        (group_id, ','.join(vendor_ids),))
        except mdb.Error as e:
            raise CursorError(cur, e)

    def remove(self, group_id):
        """ Removes the user from the userlist """
        assert group_id
        try:
            cur = self._db.cursor()
            cur.execute("DELETE FROM groups WHERE group_id=%s;", (group_id,))
        except mdb.Error as e:
            raise CursorError(cur, e)

    def set_property(self, group_id, key, value):
        """ Sets some properties on the user """
        assert group_id
        assert key
        cur = self._db.cursor()
        try:
            query = "UPDATE groups SET %s=%%s WHERE group_id=%%s;" % key
            cur.execute(query, (value, group_id,))
        except mdb.Error as e:
            raise CursorError(cur, e)

    def get_all(self):
        """ Get all the users """
        try:
            cur = self._db.cursor()
            cur.execute("SELECT group_id, vendor_ids FROM groups;")
        except mdb.Error as e:
            raise CursorError(cur, e)
        res = cur.fetchall()
        if not res:
            return []
        items = []
        for e in res:
            items.append(_create_group_id(e))
        return items

    def get_item(self, group_id, password=None):
        """ Gets information about a specific user """
        assert group_id
        try:
            cur = self._db.cursor()
            cur.execute("SELECT group_id, vendor_ids FROM groups "
                        "WHERE group_id = %s LIMIT 1;",
                        (group_id,))
        except mdb.Error as e:
            raise CursorError(cur, e)
        res = cur.fetchone()
        if not res:
            return None
        return _create_group_id(res)

class DatabaseUsers(object):

    def __init__(self, db):
        """ Constructor for object """
        self._db = db

    def get_signing_uid(self):
        """ Gets the signing UID for the site, i.e. the admin email address """
        try:
            cur = self._db.cursor()
            cur.execute("SELECT email FROM users WHERE username='admin'")
        except mdb.Error as e:
            raise CursorError(cur, e)
        key_uid = cur.fetchone()
        return key_uid[0]

    def add(self, username, password, name, email, qa_group):
        """ Adds the user to the userlist """
        assert username
        assert password
        assert name
        assert email
        assert qa_group
        pw_hash = _password_hash(password)
        try:
            cur = self._db.cursor()
            cur.execute("INSERT INTO users (username, password, display_name, "
                        "email, is_enabled, qa_group) "
                        "VALUES (%s, %s, %s, %s, 1, %s);",
                        (username, pw_hash, name, email, qa_group,))
        except mdb.Error as e:
            raise CursorError(cur, e)

    def remove(self, username):
        """ Removes the user from the userlist """
        assert username
        try:
            cur = self._db.cursor()
            cur.execute("DELETE FROM users WHERE username=%s;", (username,))
        except mdb.Error as e:
            raise CursorError(cur, e)

    def set_property(self, username, key, value):
        """ Sets some properties on the user """
        assert username
        assert key

        cur = self._db.cursor()
        try:
            query = "UPDATE users SET %s=%%s WHERE username=%%s;" % key
            if key == 'password':
                value = _password_hash(value)
            cur.execute(query, (value, username,))
        except mdb.Error as e:
            raise CursorError(cur, e)

    def is_enabled(self, username):
        """ Returns success if the username is present and enabled """
        assert username
        cur = self._db.cursor()
        try:
            cur.execute("SELECT is_enabled FROM users WHERE username=%s", (username,))
        except mdb.Error as e:
            raise CursorError(cur, e)
        auth = cur.fetchone()
        if auth:
            return True
        return False

    def verify(self, username, password):
        """ Verify that a username and password exists """
        assert username
        assert password
        pw_hash = _password_hash(password)
        try:
            cur = self._db.cursor()
            cur.execute("SELECT is_enabled FROM users WHERE username=%s AND password=%s;",
                        (username, pw_hash,))
        except mdb.Error as e:
            raise CursorError(cur, e)
        auth = cur.fetchone()
        if not auth:
            return False
        return True

    def update(self, username, password, name, email, pubkey):
        """ Update user details """
        assert username
        assert password
        assert name
        assert email
        try:
            cur = self._db.cursor()
            cur.execute("UPDATE users SET display_name=%s, email=%s, password=%s, pubkey=%s "
                        "WHERE username=%s;",
                        (name, email, _password_hash(password), pubkey, username,))
        except mdb.Error as e:
            raise CursorError(cur, e)

    def get_all(self):
        """ Get all the users """
        try:
            cur = self._db.cursor()
            cur.execute("SELECT username, display_name, email, password, "
                        "is_enabled, is_qa, qa_group, is_locked, pubkey FROM users;")
        except mdb.Error as e:
            raise CursorError(cur, e)
        res = cur.fetchall()
        if not res:
            return []
        items = []
        for e in res:
            items.append(_create_user_item(e))
        return items

    def get_item(self, username, password=None):
        """ Gets information about a specific user """
        assert username
        try:
            cur = self._db.cursor()
            if password:
                cur.execute("SELECT username, display_name, email, password, "
                            "is_enabled, is_qa, qa_group, is_locked, pubkey FROM users "
                            "WHERE username = %s AND password = %s LIMIT 1;",
                            (username, password,))
            else:
                cur.execute("SELECT username, display_name, email, password, "
                            "is_enabled, is_qa, qa_group, is_locked, pubkey FROM users "
                            "WHERE username = %s LIMIT 1;",
                            (username,))
        except mdb.Error as e:
            raise CursorError(cur, e)
        res = cur.fetchone()
        if not res:
            return None
        return _create_user_item(res)

    def get_qa_groups(self):
        """ Gets the list of QA groups """
        try:
            cur = self._db.cursor()
            cur.execute("SELECT DISTINCT qa_group FROM users;")
        except mdb.Error as e:
            raise CursorError(cur, e)
        qa_groups = []
        res = cur.fetchall()
        if not res:
            return qa_groups
        for e in res:
            qa_groups.append(e[0])
        return qa_groups

class DatabaseFirmware(object):

    def __init__(self, db):
        """ Constructor for object """
        self._db = db

    def set_target(self, fwid, target):
        """ get the number of firmware files we've provided """
        assert fwid
        assert target
        try:
            cur = self._db.cursor()
            cur.execute("UPDATE firmware SET target=%s WHERE fwid=%s;", (target, fwid,))
        except mdb.Error as e:
            raise CursorError(cur, e)

    def update(self, fwobj):
        """ Update firmware details """
        assert fwobj
        try:
            cur = self._db.cursor()
            cur.execute("UPDATE firmware SET version_display=%s "
                        "WHERE fwid=%s;",
                        (fwobj.version_display,
                         fwobj.fwid,))
            for md in fwobj.mds:
                cur.execute("UPDATE firmware_md SET description=%s, "
                            "release_description=%s, "
                            "release_urgency=%s, "
                            "release_installed_size=%s, "
                            "release_download_size=%s "
                            "WHERE fwid=%s;",
                            (md.description,
                             md.release_description,
                             md.release_urgency,
                             md.release_installed_size,
                             md.release_download_size,
                             fwobj.fwid,))
        except mdb.Error as e:
            raise CursorError(cur, e)

    def add(self, fwobj):
        """ Add a firmware object to the database """
        try:
            cur = self._db.cursor()
            cur.execute("INSERT INTO firmware (qa_group, addr, timestamp, "
                        "filename, fwid, target, version_display) "
                        "VALUES (%s, %s, CURRENT_TIMESTAMP, %s, %s, %s, %s);",
                        (fwobj.qa_group,
                         fwobj.addr,
                         fwobj.filename,
                         fwobj.fwid,
                         fwobj.target,
                         fwobj.version_display,))
            for md in fwobj.mds:
                cur.execute("INSERT INTO firmware_md (fwid, id, guid, version, "
                            "name, summary, checksum_contents, release_description, "
                            "release_timestamp, developer_name, metadata_license, "
                            "project_license, url_homepage, description, "
                            "checksum_container, filename_contents, "
                            "release_installed_size, "
                            "release_download_size, release_urgency, "
                            "screenshot_url, screenshot_caption, metainfo_id) "
                            "VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, "
                            "%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s);",
                            (fwobj.fwid,
                             md.cid,
                             ','.join(md.guids),
                             md.version,
                             md.name,
                             md.summary,
                             md.checksum_contents,
                             md.release_description,
                             md.release_timestamp,
                             md.developer_name,
                             md.metadata_license,
                             md.project_license,
                             md.url_homepage,
                             md.description,
                             md.checksum_container,
                             md.filename_contents,
                             md.release_installed_size,
                             md.release_download_size,
                             md.release_urgency,
                             md.screenshot_url,
                             md.screenshot_caption,
                             md.metainfo_id,))
        except mdb.Error as e:
            raise CursorError(cur, e)

    def remove(self, fwid):
        """ Removes firmware from the database if it exists """
        try:
            cur = self._db.cursor()
            cur.execute("DELETE FROM firmware WHERE fwid = %s;", (fwid,))
            cur.execute("DELETE FROM firmware_md WHERE fwid = %s;", (fwid,))
        except mdb.Error as e:
            raise CursorError(cur, e)

    def _add_items_md(self, item):
        try:
            cur = self._db.cursor()
            cur.execute("SELECT fwid, id, guid, version, "
                        "name, summary, checksum_contents, release_description, "
                        "release_timestamp, developer_name, metadata_license, "
                        "project_license, url_homepage, description, "
                        "checksum_container, filename_contents, "
                        "release_installed_size, release_download_size, "
                        "release_urgency, screenshot_url, screenshot_caption, "
                        "metainfo_id "
                        "FROM firmware_md WHERE fwid = %s ORDER BY guid DESC;",
                        (item.fwid,))
        except mdb.Error as e:
            raise CursorError(cur, e)
        res = cur.fetchall()
        if not res:
            return []
        for e in res:
            md = _create_firmware_md(e)
            item.mds.append(md)

    def get_all(self):
        """ Returns all firmware objects """
        try:
            cur = self._db.cursor()
            cur.execute("SELECT qa_group, addr, timestamp, "
                        "filename, fwid, target, version_display "
                        "FROM firmware ORDER BY timestamp DESC;")
        except mdb.Error as e:
            raise CursorError(cur, e)
        res = cur.fetchall()
        if not res:
            return []
        items = []
        for e in res:
            item = _create_firmware_item(e)
            items.append(item)
            self._add_items_md(item)
        return items

    def get_item(self, fwid):
        """ Gets a specific firmware object """
        items = self.get_all()
        for item in items:
            if item.fwid == fwid:
                return item
        return None

    def migrate(self):
        """ Migrates databases to latest schema """
        try:
            cur = self._db.cursor()
            cur.execute("SELECT fwid, id FROM firmware_md WHERE metainfo_id IS NULL;")
            res = cur.fetchall()
            if not res:
                return
            for e in res:
                fake_id = list(hashlib.sha1(e[0]+e[1]).hexdigest())
                for idx in range(0, 8):
                    fake_id[idx] = '0'
                cur.execute("UPDATE firmware_md SET metainfo_id=%s "
                            "WHERE fwid=%s AND id=%s;",
                            (''.join(fake_id), e[0], e[1],))
        except mdb.Error as e:
            raise CursorError(cur, e)

class DatabaseEventlog(object):

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
        except mdb.Error as e:
            raise CursorError(cur, e)

    def size(self):
        """ Gets the length of the event log """
        try:
            cur = self._db.cursor()
            cur.execute("SELECT COUNT(timestamp) FROM event_log")
        except mdb.Error as e:
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
        except mdb.Error as e:
            raise CursorError(cur, e)
        res = cur.fetchone()[0]
        if not res:
            return 0
        return res

    def get_all(self, start, length):
        """ Gets the event log items """
        try:
            cur = self._db.cursor()
            cur.execute("SELECT timestamp, username, qa_group, addr, message, is_important "
                        "FROM event_log ORDER BY id DESC LIMIT %s,%s;",
                        (start, length,))
        except mdb.Error as e:
            raise CursorError(cur, e)
        res = cur.fetchall()
        if not res:
            return []
        items = []
        for e in res:
            items.append(_create_eventlog_item(e))
        return items

    def get_all_for_qa_group(self, qa_group, start, length):
        """ Gets the event log items """
        try:
            cur = self._db.cursor()
            cur.execute("SELECT timestamp, username, qa_group, addr, message, is_important "
                        "FROM event_log WHERE qa_group = %s ORDER BY id DESC LIMIT %s,%s;",
                        (qa_group, start, length,))
        except mdb.Error as e:
            raise CursorError(cur, e)
        res = cur.fetchall()
        if not res:
            return []
        items = []
        for e in res:
            items.append(_create_eventlog_item(e))
        return items

class DatabaseClients(object):

    def __init__(self, db):
        """ Constructor for object """
        self._db = db

    def add(self, when, kind):
        """ get the number of files we've provided """
        datestr = _get_datestr_from_datetime(when)
        try:
            cur = self._db.cursor()
            cur.execute("INSERT INTO analytics (datestr,kind) VALUES (%s, %s) "
                        "ON DUPLICATE KEY UPDATE cnt=cnt+1;",
                        (datestr, kind,))
        except mdb.Error as e:
            raise CursorError(cur, e)

    def get_firmware_count_filename(self, filename):
        """ get the number of files we've provided """
        try:
            cur = self._db.cursor()
            cur.execute("SELECT DISTINCT(COUNT(addr)) FROM clients "
                        "WHERE filename = %s", (filename,))
        except mdb.Error as e:
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
                        "WHERE user_agent IS NOT NULL "
                        "GROUP BY user_agent ORDER BY COUNT(*) DESC LIMIT 6;")
        except mdb.Error as e:
            raise CursorError(cur, e)
        res = cur.fetchall()
        if not res:
            return (["No data"], [0])
        labels = []
        data = []
        for e in res:
            # split up a generic agent to a specific client
            labels.append(str(e[0].split(' ')[0]))
            data.append(int(e[1]))
        return (labels, data)

    def increment(self, address, fn=None, user_agent=None):
        """ Adds a client address into the database """
        try:
            cur = self._db.cursor()
            cur.execute("INSERT INTO clients (addr, filename, user_agent) "
                        "VALUES (%s, %s, %s);",
                        (_addr_hash(address), fn, user_agent,))
        except mdb.Error as e:
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
            except mdb.Error as e:
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
            except mdb.Error as e:
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
            except mdb.Error as e:
                raise CursorError(cur, e)
            data.append(int(cur.fetchone()[0]))
        return data
