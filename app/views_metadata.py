#!/usr/bin/python2
# -*- coding: utf-8 -*-
#
# Copyright (C) 2017-2018 Richard Hughes <richard@hughsie.com>
# Licensed under the GNU General Public License Version 2

from flask import render_template, g, make_response, flash, redirect, url_for
from flask_login import login_required

from app import app, db

from .hash import _qa_hash
from .metadata import _metadata_update_group, _metadata_update_targets, _metadata_update_pulp
from .models import UserCapability, Vendor
from .util import _error_internal, _error_permission_denied

@login_required
@app.route('/lvfs/metadata/<group_id>')
def metadata_remote(group_id):
    """
    Generate a remote file for a given QA group.
    """

    # find the vendor
    if not db.session.query(Vendor).filter(Vendor.group_id == group_id).first():
        return _error_internal('No vendor with that name')

    # generate file
    remote = []
    remote.append('[fwupd Remote]')
    remote.append('Enabled=true')
    remote.append('Title=Embargoed for ' + group_id)
    remote.append('Keyring=gpg')
    remote.append('MetadataURI=https://fwupd.org/downloads/firmware-' + _qa_hash(group_id) + '.xml.gz')
    remote.append('OrderBefore=lvfs,fwupd')
    fn = group_id + '-embargo.conf'
    response = make_response('\n'.join(remote))
    response.headers['Content-Disposition'] = 'attachment; filename=' + fn
    response.mimetype = 'text/plain'
    return response

@app.route('/lvfs/metadata')
@login_required
def metadata_view():
    """
    Show all metadata available to this user.
    """

    # show all embargo metadata URLs when admin user
    group_ids = []
    if g.user.check_capability(UserCapability.Admin):
        for vendor in db.session.query(Vendor).all():
            group_ids.append(vendor.group_id)
    else:
        group_ids.append(g.user.vendor.group_id)
    return render_template('metadata.html',
                           group_id=g.user.vendor.group_id,
                           group_ids=group_ids)

@app.route('/lvfs/metadata/rebuild')
@login_required
def metadata_rebuild():
    """
    Forces a rebuild of all metadata.
    """

    # security check
    if not g.user.check_capability(UserCapability.Admin):
        return _error_permission_denied('Only admin is allowed to force-rebuild metadata')

    # update metadata
    for vendor in db.session.query(Vendor).all():
        _metadata_update_group(vendor.group_id)
    _metadata_update_targets(['stable', 'testing'])
    _metadata_update_pulp()
    flash('Metadata rebuilt successfully', 'info')
    return redirect(url_for('.metadata_view'))
