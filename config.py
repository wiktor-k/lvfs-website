#!/usr/bin/python2
# -*- coding: utf-8 -*-
#
# Copyright (C) 2015 Richard Hughes <richard@hughsie.com>
# Licensed under the GNU General Public License Version 2

import os

if not 'OPENSHIFT_PYTHON_DIR' in os.environ:
    STATIC_DIR = 'static'
    UPLOAD_DIR = 'uploads'
    DOWNLOAD_DIR = 'downloads'
    KEYRING_DIR = 'gnupg'
    BACKUP_DIR = 'backup'
    CABEXTRACT_CMD = '/usr/bin/cabextract'
else:
    STATIC_DIR = os.path.join(os.environ['OPENSHIFT_REPO_DIR'], 'static')
    UPLOAD_DIR = os.path.join(os.environ['OPENSHIFT_DATA_DIR'], 'uploads')
    DOWNLOAD_DIR = os.path.join(os.environ['OPENSHIFT_DATA_DIR'], 'downloads')
    KEYRING_DIR = os.path.join(os.environ['OPENSHIFT_DATA_DIR'], 'gnupg')
    BACKUP_DIR = os.path.join(os.environ['OPENSHIFT_DATA_DIR'], 'backup')

    # this needs to be setup using:
    # cd app-root/data/
    # wget http://www.cabextract.org.uk/cabextract-1.6.tar.gz
    # tar xvfz cabextract-1.6.tar.gz
    # cd cabextract-1.6 && ./configure --prefix=/tmp && make
    # rm cabextract-1.6.tar.gz
    CABEXTRACT_CMD = os.path.join(os.environ['OPENSHIFT_DATA_DIR'],
                                  'cabextract-1.6',
                                  'cabextract')
