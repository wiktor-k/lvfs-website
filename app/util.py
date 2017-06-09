#!/usr/bin/python2
# -*- coding: utf-8 -*-
#
# Copyright (C) 2015 Richard Hughes <richard@hughsie.com>
# Licensed under the GNU General Public License Version 2

import hashlib
import os
import sys
import boto3

from .affidavit import Affidavit

from app import app, db

def _create_affidavit():
    """ Create an affidavit that can be used to sign files """
    key_uid = db.users.get_signing_uid()
    return Affidavit(key_uid, app.config['KEYRING_DIR'])

def _upload_to_cdn(fn, blob):
    """ Upload something to the CDN """
    if not app.config['CDN_BUCKET']:
        return
    key = os.path.join("downloads/", os.path.basename(fn))
    s3 = boto3.resource('s3')
    bucket = s3.Bucket(app.config['CDN_BUCKET'])
    bucket.Acl().put(ACL='public-read')
    print "uploading %s as %s" % (fn, key)
    obj = bucket.put_object(Key=key, Body=blob)
    obj.Acl().put(ACL='public-read')

def main():
    if len(sys.argv) != 2:
        print "usage: filename"
        return
    blob = open(sys.argv[1], 'rb').read()
    _upload_to_cdn(sys.argv[1], blob)

if __name__ == "__main__":
    main()
