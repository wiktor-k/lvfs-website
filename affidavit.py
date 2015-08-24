#!/usr/bin/python2
# Copyright (C) 2015 Richard Hughes <richard@hughsie.com>
# Licensed under the GNU General Public License Version 2

import gnupg
import os

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

def main():

    # [mine]$ gpg2 --export-secret-key > secret.key
    # [mine]$ sudo sshfs hash@instance:/var/lib/openshift/hash/app-root/data mnt
    # [mine]$ mkdir mnt/gnupg
    # [mine]$ cp secret.key mnt/gnupg
    # [mine]$ sudo umount mnt
    # [mine]$ ssh hash@instance
    # [open]$ gpg2 --homedir app-root/data/gnupg --allow-secret-key-import --import secret.key
    # [open]$ gpg2 --edit-key keyid
    # Command> passwd
    # Command> quit

    ss = Affidavit('sign-test@fwupd.org', '/home/hughsie/.gnupg')
    asc = ss.create('hello world')
    print asc

if __name__ == "__main__":
    main()
