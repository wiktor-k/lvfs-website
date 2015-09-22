#!/usr/bin/python
# -*- coding: utf-8 -*-
#
# Copyright (C) 2015 Richard Hughes <richard@hughsie.com>
# Licensed under the GNU General Public License Version 2

import sys
import ConfigParser
import StringIO

class InfParser(ConfigParser.RawConfigParser):

    def __init__(self):
        ConfigParser.RawConfigParser.__init__(self, allow_no_value=True)

    def get(self, group, key):
        val = ConfigParser.RawConfigParser.get(self, group, key)

        # handle things in localised 'Strings'
        if val.endswith('%') and val.startswith('%'):
            val = ConfigParser.RawConfigParser.get(self, 'Strings', val[1:-1])

        # format multiline comments
        fixed = []
        for ln in val.split('\n'):

            # microsoftism
            if ln.endswith('|'):
                ln = ln[:-1].strip()

            # strip double quotes
            if ln.endswith('"') and ln.startswith('"'):
                ln = ln[1:-1]
            fixed.append(ln)

        return '\n'.join(fixed)

    def read_data(self, contents):
        buf = StringIO.StringIO(contents)
        self.readfp(buf)

def main():
    cfg = InfParser()
    for fn in sys.argv[1:]:
        cfg.read(fn)
        for section in cfg.sections():
            print cfg.items(section)
        print cfg.get("Version", "CatalogFile")
        print cfg.get("Version", "Provider")

if __name__ == "__main__":
    main()
