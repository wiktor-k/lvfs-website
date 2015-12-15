#!/usr/bin/python2
# -*- coding: utf-8 -*-
#
# Copyright (C) 2015 Richard Hughes <richard@hughsie.com>
# Licensed under the GNU General Public License Version 2

import os
import appstream

from config import DOWNLOAD_DIR
from util import _qa_hash
from db import LvfsDatabase, CursorError
from db_eventlog import LvfsDatabaseEventlog
from db_firmware import LvfsDatabaseFirmware

def _generate_metadata_kind(filename, targets=None, qa_group=None):
    """ Generates AppStream metadata of a specific kind """
    db = LvfsDatabase(os.environ)
    db_firmware = LvfsDatabaseFirmware(db)
    items = db_firmware.get_items()
    store = appstream.Store('lvfs')
    for item in items:

        # filter
        if item.target == 'private':
            continue
        if targets and item.target not in targets:
            continue
        if qa_group and qa_group != item.qa_group:
            continue

        # add each component
        for md in item.mds:
            component = appstream.Component()
            component.id = md.cid
            component.kind = 'firmware'
            component.name = md.name
            component.summary = md.summary
            component.description = md.description
            if md.url_homepage:
                component.urls['homepage'] = md.url_homepage
            component.metadata_license = md.metadata_license
            component.project_license = md.project_license
            component.developer_name = md.developer_name

            # add provide
            if md.guid:
                prov = appstream.Provide()
                prov.kind = 'firmware-flashed'
                prov.value = md.guid
                component.add_provide(prov)

            # add release
            if md.version:
                rel = appstream.Release()
                rel.version = md.version
                rel.description = md.release_description
                if md.release_timestamp:
                    rel.timestamp = md.release_timestamp
                rel.checksums = []
                rel.location = 'https://secure-lvfs.rhcloud.com/downloads/' + item.filename
                rel.size_installed = md.release_installed_size
                rel.size_download = md.release_download_size
                component.add_release(rel)

                # add container checksum
                if md.checksum_container:
                    csum = appstream.Checksum()
                    csum.target = 'container'
                    csum.value = md.checksum_container
                    csum.filename = item.filename
                    rel.add_checksum(csum)

                # add content checksum
                if md.checksum_contents:
                    csum = appstream.Checksum()
                    csum.target = 'content'
                    csum.value = md.checksum_contents
                    csum.filename = md.filename_contents
                    rel.add_checksum(csum)

            # add component
            store.add(component)

    # dump to file
    if not os.path.exists(DOWNLOAD_DIR):
        os.mkdir(DOWNLOAD_DIR)
    filename = os.path.join(DOWNLOAD_DIR, filename)
    store.to_file(filename)
    return filename

def metadata_update_qa_group(qa_group):
    """ updates metadata for a specific qa_group """

    # explicit
    if qa_group:
        filename = 'firmware-%s.xml.gz' % _qa_hash(qa_group)
        _generate_metadata_kind(filename, qa_group=qa_group)
        return [os.path.join(DOWNLOAD_DIR, filename)]

    # do for all
    db = LvfsDatabase(os.environ)
    db_firmware = LvfsDatabaseFirmware(db)
    qa_groups = db_firmware.get_qa_groups()
    filenames = []
    for qa_group in qa_groups:
        filename_qa = 'firmware-%s.xml.gz' % _qa_hash(qa_group)
        filename = _generate_metadata_kind(filename_qa, qa_group=qa_group)
        filenames.append(filename)

    # return all the files we have to sign
    return filenames

def metadata_update_targets(targets):
    """ updates metadata for a specific target """
    filenames = []
    for target in targets:
        if target == 'stable':
            filename = _generate_metadata_kind('firmware.xml.gz', targets=['stable'])
            filenames.append(filename)
        elif target == 'testing':
            filename = _generate_metadata_kind('firmware-testing.xml.gz', targets=['stable', 'testing'])
            filenames.append(filename)

    # return all the files we have to sign
    return filenames
