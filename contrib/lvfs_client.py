#!/usr/bin/python3
# Copyright (C) 2015 Richard Hughes <richard@hughsie.com>
# Licensed under the GNU General Public License Version 2

import os
import requests

class LvfsClient(object):
    """ Helper object for LVFS """

    def __init__(self, server):
        """ Initialisation """

        self.users = {}
        self.server = server

        # is a hardcoded admin password available
        config_fn = os.path.join(os.path.expanduser("~"), '.config', 'lvfs.conf')
        if os.path.exists(config_fn):
            pw = open(config_fn, 'rb').read().decode('utf-8').strip()
            self.add_user('admin', 'admin', pw)

    def add_user(self, auth, username, password):
        """ Add a user to be used when contacting LVFS """
        self.users[auth] = (username, password)

    def _get_payload(self, auth):
        """ Get the authentication payload """
        if not auth in self.users:
            return {}
        data = self.users[auth]
        return {'username': data[0],
                'password': data[1]}

    def action_fwdelete(self, firmware_id, auth='user'):
        """ Delete a firmware file """
        uri = "%s/lvfs/fwdelete&id=%s&confirm=1" % (self.server, firmware_id)
        return requests.post(uri, data=self._get_payload(auth))

    def action_metadata_rebuild(self, auth='user'):
        """ Rebuild metadata """
        uri = "%s/lvfs/metadata_rebuild" % self.server
        return requests.post(uri, data=self._get_payload(auth))

    def action_useradd(self, username, password, qa_group, name, email, auth='user'):
        """ Add a user """
        uri = "%s/lvfs/user/add&username_new=%s&password_new=%s&" \
              "qa_group=%s&name=%s&email=%s" % \
              (self.server, username, password, qa_group, name, email)
        return requests.post(uri, data=self._get_payload(auth))

    def action_userdel(self, username, auth='user'):
        """ Delete a user """
        uri = "%s/lvfs/%s/delete" % (self.server, username)
        return requests.post(uri, data=self._get_payload(auth))

    def action_userinc(self, username, key, auth='user'):
        """ Increment a user """
        uri = "%s/lvfs/userinc&username_new=%s&key=%s" % (self.server, username, key)
        return requests.post(uri, data=self._get_payload(auth))

    def action_dump(self, target, auth='user'):
        """ Dump a specific target """
        uri = "%s/lvfs/dump&target=%s" % (self.server, target)
        return requests.post(uri, data=self._get_payload(auth))

    def action_upload(self, fn, target, auth='user'):
        """ Upload a new firmware file """
        try:
            f = open(fn, 'rb')
        except IOError as e:
            return None
        uri = "%s/lvfs/upload/%s" % (self.server, target)
        return requests.post(uri, data=self._get_payload(auth), files={'file': f})
