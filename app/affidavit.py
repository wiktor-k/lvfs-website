#!/usr/bin/python2
# -*- coding: utf-8 -*-
#
# Copyright (C) 2015 Richard Hughes <richard@hughsie.com>
# Licensed under the GNU General Public License Version 2

import os
import gnupg

class NoKeyError(Exception):
    pass

class Affidavit(object):
    """ A quick'n'dirty signing server """
    def __init__(self, key_uid=None, homedir='/tmp'):
        """ Set defaults """

        # check exists
        if not os.path.exists(homedir):
            os.mkdir(homedir)

        # find correct key ID for the UID
        self._keyid = None
        gpg = gnupg.GPG(gnupghome=homedir, gpgbinary='gpg2')
        for privkey in gpg.list_keys(True):
            for uid in privkey['uids']:
                if uid.find(key_uid) != -1:
                    self._keyid = privkey['keyid']
        if not self._keyid:
            raise NoKeyError('No imported private key for %s' % key_uid)
        self._homedir = homedir

    def create(self, data):
        """ Create detached signature data """
        gpg = gnupg.GPG(gnupghome=self._homedir, gpgbinary='gpg2')
        return str(gpg.sign(str(data), detach=True, keyid=self._keyid))

    def create_detached(self, filename):
        """ Create a detached signature file """
        data = open(filename).read()
        with open(filename + '.asc', 'w') as f:
            f.write(self.create(data))
        return filename + '.asc'

    def verify(self, data):
        """ Verify that the data was signed by something we trust """
        gpg = gnupg.GPG(gnupghome=self._homedir, gpgbinary='gpg2')
        ver = gpg.verify(data)
        if not ver.valid:
            raise NoKeyError('Firmware was signed with an unknown private key')
        return True

def main():
    ss = Affidavit('sign-test@fwupd.org', '/home/hughsie/.gnupg')
    asc = ss.create('hello world')
    print asc

if __name__ == "__main__":
    main()
