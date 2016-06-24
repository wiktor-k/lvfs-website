#!/usr/bin/python2
# -*- coding: utf-8 -*-
#
# Copyright (C) 2015 Richard Hughes <richard@hughsie.com>
# Licensed under the GNU General Public License Version 2

import os

if not 'OPENSHIFT_PYTHON_DIR' in os.environ:
    STATIC_DIR = 'static'
    DOWNLOAD_DIR = 'downloads'
    KEYRING_DIR = 'gnupg'
    CABEXTRACT_CMD = '/usr/bin/cabextract'
else:
    STATIC_DIR = os.path.join(os.environ['OPENSHIFT_REPO_DIR'], 'static')
    DOWNLOAD_DIR = os.path.join(os.environ['OPENSHIFT_DATA_DIR'], 'downloads')
    KEYRING_DIR = os.path.join(os.environ['OPENSHIFT_DATA_DIR'], 'gnupg')
    CABEXTRACT_CMD = os.path.join(os.environ['OPENSHIFT_DATA_DIR'],
                                  'cabextract-1.6',
                                  'cabextract')
