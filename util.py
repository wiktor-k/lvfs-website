#!/usr/bin/python2
# -*- coding: utf-8 -*-
#
# Copyright (C) 2015 Richard Hughes <richard@hughsie.com>
# Licensed under the GNU General Public License Version 2

import hashlib
import os
import boto3
import sys

def _qa_hash(value):
    """ Generate a salted hash of the QA group """
    salt = 'vendor%%%'
    return hashlib.sha1(salt + value).hexdigest()

def _upload_to_cdn(fn, blob):
    """ Upload something to the CDN """
    key = os.path.join("downloads/", os.path.basename(fn))
    s3 = boto3.resource('s3')
    bucket = s3.Bucket('lvfsbucket')
    bucket.Acl().put(ACL='public-read')
    print("uploading %s as %s" % (fn, key))
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
