#!/usr/bin/python
# -*- coding: utf-8 -*-
#
# Copyright (C) 2015 Richard Hughes <richard@hughsie.com>
# Licensed under the GNU General Public License Version 2

import MySQLdb as mdb

from db import CursorError

class LvfsFirmwareMd(object):
    def __init__(self):
        """ Constructor for object """
        self.fwid = None    # this maps the object back into a LvfsFirmware
        self.cid = None
        self.guid = None
        self.version = None
        self.name = None
        self.summary = None
        self.checksum_contents = None
        self.release_description = None
        self.release_timestamp = 0
        self.developer_name = None
        self.metadata_license = None
        self.project_license = None
        self.url_homepage = None
        self.description = None
        self.checksum_container = None
        self.filename_contents = None
        self.release_installed_size = 0
        self.release_download_size = 0
        self.release_urgency = None
    def __repr__(self):
        return "LvfsFirmwareMd object %s" % self.fwid

class LvfsFirmware(object):
    def __init__(self):
        """ Constructor for object """
        self.qa_group = None
        self.addr = None
        self.timestamp = None
        self.filename = None
        self.fwid = None
        self.target = None
        self.version_display = None
        self.mds = []
    def __repr__(self):
        return "LvfsFirmware object %s" % self.fwid

def _create_firmware_md(e):
    md = LvfsFirmwareMd()
    md.fwid = e[0]
    md.cid = e[1]
    md.guid = e[2]
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
    return md

def _create_firmware_item(e):
    item = LvfsFirmware()
    item.qa_group = e[0]
    item.addr = e[1]
    item.timestamp = e[2]
    item.filename = e[3]
    item.fwid = e[4]
    item.target = e[5]
    item.version_display = e[6]
    return item

class LvfsDatabaseFirmware(object):

    def __init__(self, db):
        """ Constructor for object """
        self._db = db

        # test firmware table exists
        try:
            cur = self._db.cursor()
            cur.execute("SELECT * FROM firmware LIMIT 1;")
        except mdb.Error, e:
            sql_db = """
                CREATE TABLE firmware (
                  qa_group VARCHAR(40) NOT NULL DEFAULT '',
                  addr VARCHAR(40) DEFAULT NULL,
                  timestamp TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
                  filename VARCHAR(255) DEFAULT NULL,
                  target VARCHAR(255) DEFAULT NULL,
                  fwid VARCHAR(40) DEFAULT NULL,
                  version_display VARCHAR(255) DEFAULT NULL,
                  UNIQUE KEY id (fwid)
                ) CHARSET=utf8;
            """
            cur.execute(sql_db)

        # FIXME: remove after a few days
        try:
            sql_db = """
                ALTER TABLE firmware ADD CONSTRAINT id UNIQUE (fwid);
            """
            cur.execute(sql_db)
        except mdb.Error, e:
            pass

        # test firmware metadata table exists
        try:
            cur = self._db.cursor()
            cur.execute("SELECT * FROM firmware_md LIMIT 1;")
        except mdb.Error, e:
            sql_db = """
                CREATE TABLE firmware_md (
                  fwid VARCHAR(40) DEFAULT NULL,
                  checksum_contents VARCHAR(40) DEFAULT NULL,
                  checksum_container VARCHAR(40) DEFAULT NULL,
                  id TEXT DEFAULT NULL,
                  name TEXT DEFAULT NULL,
                  summary TEXT DEFAULT NULL,
                  guid VARCHAR(36) DEFAULT NULL,
                  description TEXT DEFAULT NULL,
                  release_description TEXT DEFAULT NULL,
                  url_homepage TEXT DEFAULT NULL,
                  metadata_license TEXT DEFAULT NULL,
                  project_license TEXT DEFAULT NULL,
                  developer_name TEXT DEFAULT NULL,
                  filename_contents TEXT DEFAULT NULL,
                  release_timestamp INTEGER DEFAULT 0,
                  version VARCHAR(255) DEFAULT NULL,
                  release_installed_size INTEGER DEFAULT 0,
                  release_download_size INTEGER DEFAULT 0,
                  release_urgency VARCHAR(16) DEFAULT NULL,
                  UNIQUE KEY id (fwid,guid)
                ) CHARSET=utf8;
            """
            cur.execute(sql_db)

        # FIXME: remove after a few days
        try:
            sql_db = """
                ALTER TABLE firmware_md ADD CONSTRAINT id UNIQUE (fwid,guid);
            """
            cur.execute(sql_db)
        except mdb.Error, e:
            pass

        # FIXME, remove after a few days
        try:
            cur.execute("SELECT release_urgency FROM firmware_md LIMIT 1;")
        except mdb.Error, e:
            sql_db = """
                ALTER TABLE firmware_md ADD release_urgency VARCHAR(16) DEFAULT NULL;
            """
            cur.execute(sql_db)

    def set_target(self, fwid, target):
        """ get the number of firmware files we've provided """
        assert fwid
        assert target
        try:
            cur = self._db.cursor()
            cur.execute("UPDATE firmware SET target=%s WHERE fwid=%s;", (target, fwid,))
        except mdb.Error, e:
            raise CursorError(cur, e)

    def get_qa_groups(self):
        """ Get the different QA groups """
        try:
            cur = self._db.cursor()
            cur.execute("SELECT DISTINCT qa_group FROM firmware;")
        except mdb.Error, e:
            raise CursorError(cur, e)
        res = cur.fetchall()
        if not res:
            return []
        qa_groups = []
        for r in res:
            qa_groups.append(r[0])
        return qa_groups

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
                            "release_installed_size=%s, "
                            "release_download_size=%s "
                            "WHERE fwid=%s;",
                            (md.description,
                             md.release_description,
                             md.release_installed_size,
                             md.release_download_size,
                             fwobj.fwid,))
        except mdb.Error, e:
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
                            "release_download_size, release_urgency) "
                            "VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, "
                            "%s, %s, %s, %s, %s, %s, %s, %s);",
                            (fwobj.fwid,
                             md.cid,
                             md.guid,
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
                             md.release_urgency,))
        except mdb.Error, e:
            raise CursorError(cur, e)

    def remove(self, fwid):
        """ Removes firmware from the database if it exists """
        try:
            cur = self._db.cursor()
            cur.execute("DELETE FROM firmware WHERE fwid = %s;", (fwid,))
            cur.execute("DELETE FROM firmware_md WHERE fwid = %s;", (fwid,))
        except mdb.Error, e:
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
                        "release_urgency "
                        "FROM firmware_md WHERE fwid = %s ORDER BY guid DESC;",
                        (item.fwid,))
        except mdb.Error, e:
            raise CursorError(cur, e)
        res = cur.fetchall()
        if not res:
            return []
        items = []
        for e in res:
            md = _create_firmware_md(e)
            item.mds.append(md)

    def get_items(self):
        """ Returns all firmware objects """
        try:
            cur = self._db.cursor()
            cur.execute("SELECT qa_group, addr, timestamp, "
                        "filename, fwid, target, version_display "
                        "FROM firmware ORDER BY timestamp DESC;")
        except mdb.Error, e:
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
        items = self.get_items()
        for item in items:
            if item.fwid == fwid:
                return item
        return None
