#!/usr/bin/python
# -*- coding: utf-8 -*-
#
# Copyright (C) 2015 Richard Hughes <richard@hughsie.com>
# Licensed under the GNU General Public License Version 2

import MySQLdb as mdb

from db import CursorError

class LvfsFirmware(object):
    def __init__(self):
        """ Constructor for object """
        self.qa_group = None
        self.addr = None
        self.timestamp = None
        self.filename = None
        self.fwid = None
        self.target = None
        self.download_cnt = 0
        self.md_id = None
        self.md_guid = None
        self.md_version = None
        self.md_version_display = None
        self.md_name = None
        self.md_summary = None
        self.md_checksum_contents = None
        self.md_release_description = None
        self.md_release_timestamp = 0
        self.md_developer_name = None
        self.md_metadata_license = None
        self.md_project_license = None
        self.md_url_homepage = None
        self.md_description = None
        self.md_checksum_container = None
        self.md_filename_contents = None
    def __repr__(self):
        return "LvfsFirmware object %s" % self.fwid

def _create_firmware_item(e):
    item = LvfsFirmware()
    item.qa_group = e[0]
    item.addr = e[1]
    item.timestamp = e[2]
    item.filename = e[3]
    item.fwid = e[4]
    item.target = e[5]
    item.md_id = e[6]
    item.md_guid = e[7]
    item.md_version = e[8]
    item.md_name = e[9]
    item.md_summary = e[10]
    item.md_checksum_contents = e[11]
    item.md_release_description = e[12]
    item.md_release_timestamp = e[13]
    item.md_developer_name = e[14]
    item.md_metadata_license = e[15]
    item.md_project_license = e[16]
    item.md_url_homepage = e[17]
    item.md_description = e[18]
    item.md_checksum_container = e[19]
    item.md_filename_contents = e[20]
    item.download_cnt = e[21]
    item.md_version_display = e[22]
    return item

class LvfsDatabaseFirmware(object):

    def __init__(self, db):
        """ Constructor for object """
        self._db = db

        # test firmware list exists
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
                  hash VARCHAR(40) DEFAULT NULL,
                  download_cnt INTEGER DEFAULT 0,
                  md_checksum_contents VARCHAR(40) DEFAULT NULL,
                  md_checksum_container VARCHAR(40) DEFAULT NULL,
                  md_id TEXT DEFAULT NULL,
                  md_name TEXT DEFAULT NULL,
                  md_summary TEXT DEFAULT NULL,
                  md_guid VARCHAR(36) DEFAULT NULL,
                  md_description TEXT DEFAULT NULL,
                  md_release_description TEXT DEFAULT NULL,
                  md_url_homepage TEXT DEFAULT NULL,
                  md_metadata_license TEXT DEFAULT NULL,
                  md_project_license TEXT DEFAULT NULL,
                  md_developer_name TEXT DEFAULT NULL,
                  md_filename_contents TEXT DEFAULT NULL,
                  md_release_timestamp INTEGER DEFAULT 0,
                  md_version VARCHAR(255) DEFAULT NULL,
                  md_version_display VARCHAR(255) DEFAULT NULL
                ) CHARSET=utf8;
            """
            cur.execute(sql_db)

         # FIXME, remove after a few days
        try:
            cur.execute("SELECT md_version_display FROM firmware LIMIT 1;")
        except mdb.Error, e:
            sql_db = """
                ALTER TABLE firmware ADD md_version_display VARCHAR(255) DEFAULT NULL;
            """
            cur.execute(sql_db)

        # fixup NULL fields
        try:
            cur.execute("SELECT * FROM firmware WHERE md_filename_contents IS NULL;")
            if cur.fetchone():
                sql_db = "UPDATE firmware SET md_filename_contents='firmware.bin' " \
                         "WHERE md_filename_contents IS NULL;"
                cur.execute(sql_db)
        except mdb.Error, e:
            pass

    def increment_filename_cnt(self, filename):
        """ Increment the downloaded count """
        assert filename
        try:
            cur = self._db.cursor()
            cur.execute("UPDATE firmware SET download_cnt = download_cnt + 1 "
                        "WHERE filename=%s", (filename,))
        except mdb.Error, e:
            raise CursorError(cur, e)

    def get_download_cnt(self):
        """ get the number of firmware files we've provided """
        try:
            cur = self._db.cursor()
            cur.execute("SELECT SUM(download_cnt) FROM firmware")
        except mdb.Error, e:
            raise CursorError(cur, e)
        download_cnt = cur.fetchone()[0]
        if not download_cnt:
            return 0
        return download_cnt

    def set_target(self, fwid, target):
        """ get the number of firmware files we've provided """
        assert fwid
        assert target
        try:
            cur = self._db.cursor()
            cur.execute("UPDATE firmware SET target=%s WHERE hash=%s;", (target, fwid,))
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
            cur.execute("UPDATE firmware SET md_description=%s, md_release_description=%s "
                        "WHERE hash=%s;",
                        (fwobj.md_description,
                         fwobj.md_release_description,
                         fwobj.fwid,))
        except mdb.Error, e:
            raise CursorError(cur, e)

    def add(self, fwobj):
        """ Add a firmware object to the database """
        try:
            cur = self._db.cursor()
            cur.execute("INSERT INTO firmware (qa_group, addr, timestamp, "
                        "filename, hash, target, md_id, md_guid, md_version, "
                        "md_name, md_summary, md_checksum_contents, md_release_description, "
                        "md_release_timestamp, md_developer_name, md_metadata_license, "
                        "md_project_license, md_url_homepage, md_description, "
                        "md_checksum_container, md_filename_contents, md_version_display) "
                        "VALUES (%s, %s, CURRENT_TIMESTAMP, %s, %s, %s, %s, "
                        "%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s);",
                        (fwobj.qa_group,
                         fwobj.addr,
                         fwobj.filename,
                         fwobj.fwid,
                         fwobj.target,
                         fwobj.md_id,
                         fwobj.md_guid,
                         fwobj.md_version,
                         fwobj.md_name,
                         fwobj.md_summary,
                         fwobj.md_checksum_contents,
                         fwobj.md_release_description,
                         fwobj.md_release_timestamp,
                         fwobj.md_developer_name,
                         fwobj.md_metadata_license,
                         fwobj.md_project_license,
                         fwobj.md_url_homepage,
                         fwobj.md_description,
                         fwobj.md_checksum_container,
                         fwobj.md_filename_contents,
                         fwobj.md_version_display,))
        except mdb.Error, e:
            raise CursorError(cur, e)

    def remove(self, fwid):
        """ Removes firmware from the database if it exists """
        try:
            cur = self._db.cursor()
            cur.execute("DELETE FROM firmware WHERE hash = %s;", (fwid,))
        except mdb.Error, e:
            raise CursorError(cur, e)

    def get_items(self):
        """ Returns all firmware objects """
        try:
            cur = self._db.cursor()
            cur.execute("SELECT qa_group, addr, timestamp, "
                        "filename, hash, target, md_id, md_guid, md_version, "
                        "md_name, md_summary, md_checksum_contents, md_release_description, "
                        "md_release_timestamp, md_developer_name, md_metadata_license, "
                        "md_project_license, md_url_homepage, md_description, "
                        "md_checksum_container, md_filename_contents, "
                        "download_cnt, md_version_display "
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
        return items

    def get_item(self, fwid):
        """ Gets a specific firmware object """
        items = self.get_items()
        for item in items:
            if item.fwid == fwid:
                return item
        return None
