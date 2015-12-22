#!/usr/bin/python2
# -*- coding: utf-8 -*-
#
# Copyright (C) 2015 Richard Hughes <richard@hughsie.com>
# Licensed under the GNU General Public License Version 2

import os
import gzip
import datetime

from config import BACKUP_DIR
from db import LvfsDatabase

def _create_backup(filename, include_clients=False):
    """ Create a checkpoint """

    # ensure directory exists
    if not os.path.exists(BACKUP_DIR):
        os.mkdir(BACKUP_DIR)

    # does the file already exists right now?
    if os.path.exists(filename):
        return False

    # save
    db = LvfsDatabase(os.environ)
    content = db.generate_backup(include_clients)
    with gzip.open(filename, 'wb') as f:
        f.write(content.encode('utf8'))
    return True

def ensure_checkpoint():
    """ Create a checkpoint """

    # an empty message indicates that nothing needed to be done
    msg = None

    # use mysqldump instead
    return msg

    # checkpointing happens up to once per minute
    now = datetime.datetime.now()
    filename = BACKUP_DIR + "/restore_" + now.strftime("%Y%m%d%H%M") + ".sql.gz"
    if _create_backup(filename):
        msg = 'Created restore checkpoint'

    # full backups happens up to once per week
    now = datetime.datetime.now()
    filename = BACKUP_DIR + "/backup_week" + now.strftime("%W") + ".sql.gz"
    if _create_backup(filename, True):
        msg = 'Created weekly backup'

    # the weekly backup message is more important and overwrites the checkpoint
    return msg
