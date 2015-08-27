#!/usr/bin/python
# -*- coding: utf-8 -*-
#
# Copyright (C) 2015 Richard Hughes <richard@hughsie.com>
# Licensed under the GNU General Public License Version 2

import MySQLdb as mdb
import hashlib

from db import CursorError

def _password_hash(value):
    """ Generate a salted hash of the password string """
    salt = 'lvfs%%%'
    return hashlib.sha1(salt + value).hexdigest()

def _create_user_item(e):
    """ Create a user object from the results """
    item = LvfsUser()
    item.username = e[0]
    item.display_name = e[1]
    item.email = e[2]
    item.password = e[3]
    item.is_enabled = bool(e[4])
    item.is_qa = bool(e[5])
    item.qa_group = e[6]
    return item

class LvfsUser(object):
    def __init__(self):
        """ Constructor for object """
        self.username = None
        self.password = None
        self.display_name = None
        self.email = None
        self.is_enabled = False
        self.is_qa = False
        self.qa_group = None
    def __repr__(self):
        return "LvfsUser object %s" % self.username

class LvfsDatabaseUsers(object):

    def __init__(self, db):
        """ Constructor for object """
        self._db = db

        # test user list exists
        try:
            cur = self._db.cursor()
            cur.execute("SELECT * FROM users LIMIT 1;")
        except mdb.Error, e:
            sql_db = """
                CREATE TABLE users (
                  username VARCHAR(40) NOT NULL DEFAULT '',
                  password VARCHAR(40) NOT NULL DEFAULT '',
                  display_name VARCHAR(128) DEFAULT NULL,
                  email VARCHAR(255) DEFAULT NULL,
                  is_enabled TINYINT DEFAULT 0,
                  is_qa TINYINT DEFAULT 0,
                  qa_group VARCHAR(40) NOT NULL DEFAULT ''
                ) CHARSET=utf8;
            """
            cur.execute(sql_db)

        # ensure an admin user always exists
        cur.execute("SELECT is_enabled FROM users WHERE username='admin';")
        if not cur.fetchone():
            sql_db = """
                INSERT INTO users (username, password, display_name, email, is_enabled, is_qa, qa_group)
                    VALUES ('admin', 'Pa$$w0rd', 'Admin User', 'sign-test@fwupd.org', 1, 1, 'admin');
            """
            cur.execute(sql_db)

        # convert legacy passwords from strings to hashes
        cur.execute("SELECT username, password FROM users;")
        res = cur.fetchall()
        for l in res:
            if len(l[1]) == 40:
                continue
            cur.execute("UPDATE users SET password=%s WHERE username=%s;",
                        (_password_hash(l[1]), l[0],))

        # ensure admin has all privs
        cur.execute("UPDATE users SET is_enabled=1, is_qa=1, qa_group='admin' "
                    "WHERE username='admin';")

    def get_signing_uid(self):
        """ Gets the signing UID for the site, i.e. the admin email address """
        try:
            cur = self._db.cursor()
            cur.execute("SELECT email FROM users WHERE username='admin'")
        except mdb.Error, e:
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
            cur.execute("INSERT INTO users (username, password, display_name, email, is_enabled, qa_group) "
                        "VALUES (%s, %s, %s, %s, 1, %s);",
                        (username, pw_hash, name, email, qa_group,))
        except mdb.Error, e:
            raise CursorError(cur, e)

    def remove(self, username):
        """ Removes the user from the userlist """
        assert username
        try:
            cur = self._db.cursor()
            cur.execute("DELETE FROM users WHERE username=%s;", (username,))
        except mdb.Error, e:
            raise CursorError(cur, e)

    def set_property(self, username, key, value):
        """ Sets some properties on the user """
        assert username
        assert key

        cur = self._db.cursor()
        if key == 'qa':
            try:
                cur.execute("UPDATE users SET is_qa=%s WHERE username=%s;",
                            (value, username,))
            except mdb.Error, e:
                raise CursorError(cur, e)
        elif key == 'enabled':
            try:
                cur.execute("UPDATE users SET is_enabled=%s WHERE username=%s;",
                            (value, username,))
            except mdb.Error, e:
                raise CursorError(cur, e)
        else:
            raise RuntimeError('Unable to change user as key invalid')

    def is_enabled(self, username):
        """ Returns success if the username is present and enabled """
        assert username
        cur = self._db.cursor()
        try:
            cur.execute("SELECT is_enabled FROM users WHERE username=%s", (username,))
        except mdb.Error, e:
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
        except mdb.Error, e:
            raise CursorError(cur, e)
        auth = cur.fetchone()
        if not auth:
            return False
        return True

    def update(self, username, password, name, email):
        """ Update user details """
        assert username
        assert password
        assert name
        assert email
        try:
            cur = self._db.cursor()
            cur.execute("UPDATE users SET display_name=%s, email=%s, password=%s "
                        "WHERE username=%s;",
                        (name, email, _password_hash(password), username,))
        except mdb.Error, e:
            raise CursorError(cur, e)

    def get_items(self):
        """ Get all the users """
        try:
            cur = self._db.cursor()
            cur.execute("SELECT username, display_name, email, password, "
                        "is_enabled, is_qa, qa_group FROM users;")
        except mdb.Error, e:
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
                            "is_enabled, is_qa, qa_group FROM users "
                            "WHERE username = %s AND password = %s LIMIT 1;",
                            (username, password,))
            else:
                cur.execute("SELECT username, display_name, email, password, "
                            "is_enabled, is_qa, qa_group FROM users "
                            "WHERE username = %s LIMIT 1;",
                            (username,))
        except mdb.Error, e:
            raise CursorError(cur, e)
        res = cur.fetchone()
        if not res:
            return None
        return _create_user_item(res)
