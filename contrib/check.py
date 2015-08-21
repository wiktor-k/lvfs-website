#!/usr/bin/python
# Copyright (C) 2015 Richard Hughes <richard@hughsie.com>
# Licensed under the GNU General Public License Version 2

import os
import sys
from lvfs_client import LvfsClient

#SERVER = 'https://testing-lvfs.rhcloud.com'
SERVER = 'http://localhost:8051'

FILE = '/home/hughsie/Code/ColorHug/ColorHug2/firmware-releases/2.0.3/hughski-colorhug2-2.0.3.cab'

def main():

    w = LvfsClient(SERVER)
    w.add_user('user', 'test', 'Pa$$w0rd')

    # set up tests to ensure the file is really gone
    w.action_fwdelete('3d69d6c68c915d7cbb4faa029230c92933263f42', auth='admin')
    w.action_userdel('test', auth='admin')

    # no auth
    r = w.action_useradd('test', 'test', 'test', 'Test User', 'test@user.com', auth='none')
    assert r.status_code == 401, "expected error when adding user"

    # only admin auth
    r = w.action_useradd('test', 'test', 'test', 'Test User', 'test@user.com', auth='user')
    assert r.status_code == 401, "expected error when adding user"

    # admin, bad password
    r = w.action_useradd('test', 'test', 'test', 'Test User', 'test@user.com', auth='admin')
    assert r.status_code == 400, "expected error when adding bad password : %s" % r.status_code

    # admin, good password, bad email
    r = w.action_useradd('test', 'Pa$$w0rd', 'test', 'Test User', 'invalid', auth='admin')
    assert r.status_code == 400, "expected error when adding bad email : %s" % r.status_code

    # admin, good password, good email, bad qa_group
    r = w.action_useradd('test', 'Pa$$w0rd', '', 'Test User', 'test@user.com', auth='admin')
    assert r.status_code == 401, "expected error when adding bad qa_group : %s" % r.status_code

    # admin, good password, good email
    r = w.action_useradd('test', 'Pa$$w0rd', 'test', 'Test User', 'test@user.com', auth='admin')
    assert r.status_code == 201, "failed to add user : %s" % r.text

    # get an error when deleting an unknown id
    r = w.action_fwdelete('deadbeef')
    assert r.status_code == 400, "expected error when deleting random id"

    # upload new fw to stable as a non QA user
    r = w.action_upload(FILE, 'stable')
    assert r.status_code == 401, "expected error when !QA upload file to stable"

    # upload random fw
    r = w.action_upload('./check.py', 'testing')
    assert r.status_code == 415, "expected error when uploading random file : %s" % r.status_code

    # upload new fw
    r = w.action_upload(FILE, 'testing')
    assert r.status_code == 201, "failed to upload file"

    # upload existing fw again
    r = w.action_upload(FILE, 'testing')
    assert r.status_code == 422, "expected error when reuploading file"

    # delete the test file without login
    r = w.action_fwdelete('3d69d6c68c915d7cbb4faa029230c92933263f42', auth='none')
    assert r.status_code == 401, "expected error when deleting file without login"

    # make the user part of QA
    r = w.action_userinc('test', 'qa', auth='none')
    assert r.status_code == 401, "expected error when inc user"
    r = w.action_userinc('test', 'qa', auth='user')
    assert r.status_code == 401, "expected error when inc user"
    r = w.action_userinc('test', 'qa', auth='admin')
    assert r.status_code == 200, "cannot inc user : %s" % r.status_code
    r = w.action_userinc('test', 'dave', auth='admin')
    assert r.status_code == 401, "expected error when inc user"

    # dump the stable firmware
    r = w.action_dump('testing', auth='none')
    assert r.status_code == 200, "failed to dump testing : %s" % r.status_code
    assert r.text.find(os.path.basename(FILE)) != -1, "failed to find fn in dump: %s" % r.text

    r = w.action_dump('embargoed', auth='none')
    assert r.status_code == 401, "expected error when dumping embargoed"
    r = w.action_dump('a94a8fe5ccb19ba61c4c0873d391e987982fbbd3', auth='none')
    assert r.status_code == 200, "expected file list for embargoed hash"
    assert r.text.find(os.path.basename(FILE)) != -1, "failed to find fn in dump: %s" % r.text

    # delete the test file
    r = w.action_fwdelete('3d69d6c68c915d7cbb4faa029230c92933263f42')
    assert r.status_code == 200, "failed to delete file"

    # delete the test user
    r = w.action_userdel('test', auth='admin')
    assert r.status_code == 200, "failed to delete test user"

if __name__ == "__main__":
    main()

