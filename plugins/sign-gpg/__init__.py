#!/usr/bin/python2
# -*- coding: utf-8 -*-
#
# Copyright (C) 2018 Richard Hughes <richard@hughsie.com>
# Licensed under the GNU General Public License Version 2
#
# pylint: disable=no-self-use

from __future__ import print_function

import os
import gnupg

from app.pluginloader import PluginBase, PluginError, PluginSettingText, PluginSettingBool
from app import ploader
from app.util import _get_settings
from app.util import _get_basename_safe, _archive_add, _archive_get_files_from_glob

class Affidavit(object):

    """ A quick'n'dirty signing server """
    def __init__(self, key_uid=None, homedir='/tmp'):
        """ Set defaults """

        # check exists
        if not os.path.exists(homedir):
            try:
                os.mkdir(homedir)
            except OSError as e:
                raise PluginError(e)

        # find correct key ID for the UID
        self._keyid = None
        gpg = gnupg.GPG(gnupghome=homedir, gpgbinary='gpg2')
        for privkey in gpg.list_keys(True):
            for uid in privkey['uids']:
                if uid.find(key_uid) != -1:
                    self._keyid = privkey['keyid']
        if not self._keyid:
            raise PluginError('No imported private key for %s' % key_uid)
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
            raise PluginError('Firmware was signed with an unknown private key')
        return True

class Plugin(PluginBase):
    def __init__(self):
        PluginBase.__init__(self)

    def name(self):
        return 'GPG'

    def summary(self):
        return 'Sign files using GnuPG, a free implementation of the OpenPGP standard.'

    def settings(self):
        s = []
        s.append(PluginSettingBool('sign_gpg_enable', 'Enabled', False))
        s.append(PluginSettingText('sign_gpg_keyring_dir', 'Keyring Directory',
                                   '/var/www/lvfs/.gnupg'))
        s.append(PluginSettingText('sign_gpg_firmware_uid', 'Signing UID for firmware',
                                   'sign-test@fwupd.org'))
        s.append(PluginSettingText('sign_gpg_metadata_uid', 'Signing UID for metadata',
                                   'sign-test@fwupd.org'))
        return s

    def _metadata_modified(self, fn):

        # plugin not enabled
        settings = _get_settings('sign_gpg')
        if settings['sign_gpg_enable'] != 'enabled':
            return

        # generate
        if not settings['sign_gpg_keyring_dir']:
            raise PluginError('No keyring directory set')
        if not settings['sign_gpg_metadata_uid']:
            raise PluginError('No metadata signing UID set')
        affidavit = Affidavit(settings['sign_gpg_metadata_uid'], settings['sign_gpg_keyring_dir'])
        if not affidavit:
            return
        blob = open(fn, 'rb').read()
        blob_asc = affidavit.create(blob)
        fn_asc = fn + '.asc'
        with open(fn_asc, 'w') as f:
            f.write(blob_asc)

        # inform the plugin loader
        ploader.file_modified(fn_asc)

    def file_modified(self, fn):
        if fn.endswith('.xml.gz'):
            self._metadata_modified(fn)

    def archive_sign(self, arc, firmware_cff):

        # plugin not enabled
        settings = _get_settings('sign_gpg')
        if settings['sign_gpg_enable'] != 'enabled':
            return

        # already signed
        detached_fn = _get_basename_safe(firmware_cff.get_name() + '.asc')
        if _archive_get_files_from_glob(arc, detached_fn):
            return

        # create the detached signature
        if not settings['sign_gpg_keyring_dir']:
            raise PluginError('No keyring directory set')
        if not settings['sign_gpg_firmware_uid']:
            raise PluginError('No firmware signing UID set')
        affidavit = Affidavit(settings['sign_gpg_firmware_uid'], settings['sign_gpg_keyring_dir'])
        contents = firmware_cff.get_bytes().get_data()
        contents_asc = affidavit.create(contents)

        # add it to the archive
        _archive_add(arc, detached_fn, contents_asc.encode('utf-8'))
