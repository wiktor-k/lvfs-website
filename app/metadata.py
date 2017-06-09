#!/usr/bin/python2
# -*- coding: utf-8 -*-
#
# Copyright (C) 2015 Richard Hughes <richard@hughsie.com>
# Licensed under the GNU General Public License Version 2

import os
import hashlib
import appstream

from app import app, db

from .hash import _qa_hash
from .util import _upload_to_cdn, _create_affidavit

def _generate_metadata_kind(filename, targets=None, group_id=None, affidavit=None):
    """ Generates AppStream metadata of a specific kind """
    items = db.firmware.get_all()
    store = appstream.Store('lvfs')
    for item in items:

        # filter
        if item.target == 'private':
            continue
        if targets and item.target not in targets:
            continue
        if group_id and group_id != item.group_id:
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
            for guid in md.guids:
                prov = appstream.Provide()
                prov.kind = 'firmware-flashed'
                prov.value = guid
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
                rel.urgency = md.release_urgency
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

            # add screenshot
            if md.screenshot_caption:
                ss = appstream.Screenshot()
                ss.caption = md.screenshot_caption
                if md.screenshot_url:
                    im = appstream.Image()
                    im.url = md.screenshot_url
                    ss.add_image(im)
                component.add_screenshot(ss)

            # add requires for each allowed vendor_ids
            group = db.groups.get_item(item.group_id)
            if group.vendor_ids:
                req = appstream.Require()
                req.kind = 'firmware'
                req.value = 'vendor-id'
                if len(group.vendor_ids) == 1:
                    req.compare = 'eq'
                else:
                    req.compare = 'regex'
                req.version = '|'.join(group.vendor_ids)
                component.add_require(req)

            # add component
            store.add(component)

    # dump to file
    download_dir = app.config['DOWNLOAD_DIR']
    if not os.path.exists(download_dir):
        os.mkdir(download_dir)
    filename = os.path.join(download_dir, filename)
    store.to_file(filename)

    # upload to the CDN
    blob = open(filename, 'rb').read()
    _upload_to_cdn(filename, blob)

    # generate and upload the detached signature
    if affidavit:
        blob_asc = affidavit.create(blob)
        _upload_to_cdn(filename + '.asc', blob_asc)

def metadata_update_group_id(group_id):
    """ updates metadata for a specific group_id """

    # explicit
    affidavit = _create_affidavit()
    if group_id:
        filename = 'firmware-%s.xml.gz' % _qa_hash(group_id)
        _generate_metadata_kind(filename,
                                group_id=group_id,
                                affidavit=affidavit)
        return

    # do for all
    group_ids = db.users.get_group_ids()
    for group_id in group_ids:
        filename_qa = 'firmware-%s.xml.gz' % _qa_hash(group_id)
        _generate_metadata_kind(filename_qa,
                                group_id=group_id,
                                affidavit=affidavit)

def metadata_update_targets(targets):
    """ updates metadata for a specific target """
    affidavit = _create_affidavit()
    for target in targets:
        if target == 'stable':
            _generate_metadata_kind('firmware.xml.gz',
                                    targets=['stable'],
                                    affidavit=affidavit)
        elif target == 'testing':
            _generate_metadata_kind('firmware-testing.xml.gz',
                                    targets=['stable', 'testing'],
                                    affidavit=affidavit)

def _hashfile(afile, hasher, blocksize=65536):
    buf = afile.read(blocksize)
    while len(buf) > 0:
        hasher.update(buf)
        buf = afile.read(blocksize)
    return hasher.hexdigest()

def metadata_update_pulp():
    """ updates metadata for Pulp """
    items = db.firmware.get_all()
    files_to_scan = []
    files_to_scan.append('firmware.xml.gz')
    files_to_scan.append('firmware.xml.gz.asc')
    for item in items:
        if item.target != 'stable':
            continue
        files_to_scan.append(item.filename)

    # for each file in stable plus metadata
    data = []
    download_dir = app.config['DOWNLOAD_DIR']
    for f in files_to_scan:
        fn = os.path.join(download_dir, f)
        if not os.path.exists(fn):
            continue

        # filename,sha256,size
        sha256 = _hashfile(open(fn, 'rb'), hashlib.sha256())
        fn_sz = os.path.getsize(fn)
        data.append('%s,%s,%i\n' % (f, sha256, fn_sz))

    # write file
    filename = os.path.join(download_dir, 'PULP_MANIFEST')
    f = open(filename, 'w')
    f.writelines(data)
    f.close()

    # upload to CDN
    blob = open(filename, 'rb').read()
    _upload_to_cdn(filename, blob)
    return
