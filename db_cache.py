#!/usr/bin/python
# -*- coding: utf-8 -*-
#
# Copyright (C) 2015 Richard Hughes <richard@hughsie.com>
# Licensed under the GNU General Public License Version 2

import os
import MySQLdb as mdb

from db import LvfsDatabase, CursorError

class LvfsDatabaseCache(object):

    def __init__(self, db):
        """ Constructor for object """
        self._db = db

    def delete(self, filename):
        """ Deletes any DB cache for the filename """
        assert filename
        basename = os.path.basename(filename)
        try:
            cur = self._db.cursor()
            cur.execute("DELETE FROM cache WHERE filename=%s;", (basename,))
        except mdb.Error, e:
            raise CursorError(cur, e)

    def from_file(self, filename):
        """ Creates an item in the database with the file contents """
        basename = os.path.basename(filename)
        data = open(filename, 'rb').read()
        try:
            cur = self._db.cursor()
            cur.execute("REPLACE INTO cache(filename,data) "
                        "VALUES(%s,%s);", (basename, data,))
        except mdb.Error, e:
            raise CursorError(cur, e)

    def to_file(self, filename, force_overwrite=False):
        """ Creates an item on disk from the database copy """

        # already exists
        if os.path.exists(filename) and not force_overwrite:
            return

        # recover from database
        basename = os.path.basename(filename)
        try:
            cur = self._db.cursor()
            cur.execute("SELECT data FROM cache WHERE filename=%s", (basename,))
        except mdb.Error, e:
            raise CursorError(cur, e)
        data = cur.fetchone()
        open(filename, 'wb').write(data[0])

def main():

    db = LvfsDatabase(os.environ)
    cache = LvfsDatabaseCache(db)

    cache.from_file('./README.md')
    cache.from_file('./README.md')

    if os.path.exists('/tmp/README.md'):
        os.remove('/tmp/README.md')
    cache.to_file('/tmp/README.md')
    cache.to_file('/tmp/README.md')
    cache.delete('README.md')

if __name__ == "__main__":
    main()
