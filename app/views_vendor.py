#!/usr/bin/python2
# -*- coding: utf-8 -*-
#
# Copyright (C) 2017 Richard Hughes <richard@hughsie.com>
# Licensed under the GNU General Public License Version 2

import os

from flask import request, flash, url_for, redirect, render_template, g
from flask_login import login_required

from app import app, db

from .util import _error_permission_denied, _error_internal
from .models import UserCapability, Vendor, Restriction

# sort by awesomeness
def _sort_vendor_func(a, b):
    a_val = a.get_sort_key()
    b_val = b.get_sort_key()
    if a_val > b_val:
        return -1
    if a_val < b_val:
        return 1
    return 0

@app.route('/status')
@app.route('/vendorlist') # deprecated
@app.route('/lvfs/vendorlist')
def vendor_list():
    vendors = db.session.query(Vendor).order_by(Vendor.display_name).all()
    vendors.sort(_sort_vendor_func)
    return render_template('vendorlist.html', vendors=vendors)

@app.route('/lvfs/vendor/add', methods=['GET', 'POST'])
@login_required
def vendor_add():
    """ Add a vendor [ADMIN ONLY] """

    # only accept form data
    if request.method != 'POST':
        return redirect(url_for('.vendor_list'))

    # security check
    if not g.user.check_capability(UserCapability.Admin):
        return _error_permission_denied('Unable to add vendor as non-admin')

    if not 'group_id' in request.form:
        return _error_permission_denied('Unable to add vendor as no data')
    if db.session.query(Vendor).filter(Vendor.group_id == request.form['group_id']).first():
        flash('Failed to add vendor: Group ID already exists', 'warning')
        return redirect(url_for('.vendor_list'), 302)
    v = Vendor(request.form['group_id'])
    db.session.add(v)
    db.session.commit()
    flash('Added vendor %s' % request.form['group_id'], 'info')
    return redirect(url_for('.vendor_details', vendor_id=v.vendor_id), 302)

@app.route('/lvfs/vendor/<int:vendor_id>/delete')
@login_required
def vendor_delete(vendor_id):
    """ Removes a vendor [ADMIN ONLY] """

    # security check
    if not g.user.check_capability(UserCapability.Admin):
        return _error_permission_denied('Unable to remove vendor as non-admin')
    vendor = db.session.query(Vendor).filter(Vendor.vendor_id == vendor_id).first()
    if not vendor:
        flash('Failed to delete vendor: No a vendor with that group ID', 'warning')
        return redirect(url_for('.vendor_list'), 302)
    db.session.delete(vendor)
    db.session.commit()
    flash('Removed vendor', 'info')
    return redirect(url_for('.vendor_list'), 302)

@app.route('/lvfs/vendor/<int:vendor_id>/details')
@login_required
def vendor_details(vendor_id):
    """ Allows changing a vendor [ADMIN ONLY] """

    # security check
    if not g.user.check_capability(UserCapability.Admin):
        return _error_permission_denied('Unable to edit vendor as non-admin')
    vendor = db.session.query(Vendor).filter(Vendor.vendor_id == vendor_id).first()
    if not vendor:
        flash('Failed to get vendor details: No a vendor with that group ID', 'warning')
        return redirect(url_for('.vendor_list'), 302)
    return render_template('vendor-details.html', v=vendor)

@app.route('/lvfs/vendor/<int:vendor_id>/restrictions')
@login_required
def vendor_restrictions(vendor_id):
    """ Allows changing a vendor [ADMIN ONLY] """

    # security check
    if not g.user.check_capability(UserCapability.Admin):
        return _error_permission_denied('Unable to edit vendor as non-admin')
    vendor = db.session.query(Vendor).filter(Vendor.vendor_id == vendor_id).first()
    if not vendor:
        flash('Failed to get vendor details: No a vendor with that group ID', 'warning')
        return redirect(url_for('.vendor_list'), 302)
    return render_template('vendor-restrictions.html', v=vendor)

@app.route('/lvfs/vendor/<int:vendor_id>/users')
@login_required
def vendor_users(vendor_id):
    """ Allows changing a vendor [ADMIN ONLY] """

    # security check
    if not g.user.check_capability(UserCapability.Admin):
        return _error_permission_denied('Unable to edit vendor as non-admin')
    vendor = db.session.query(Vendor).filter(Vendor.vendor_id == vendor_id).first()
    if not vendor:
        flash('Failed to get vendor details: No a vendor with that group ID', 'warning')
        return redirect(url_for('.vendor_list'), 302)
    return render_template('vendor-users.html', v=vendor)

@app.route('/lvfs/vendor/<int:vendor_id>/restriction/add', methods=['POST'])
@login_required
def vendor_restriction_add(vendor_id):
    """ Allows changing a vendor [ADMIN ONLY] """

    # security check
    if not g.user.check_capability(UserCapability.Admin):
        return _error_permission_denied('Unable to edit vendor as non-admin')
    vendor = db.session.query(Vendor).filter(Vendor.vendor_id == vendor_id).first()
    if not vendor:
        flash('Failed to get vendor details: No a vendor with that group ID', 'warning')
        return redirect(url_for('.vendor_list'), 302)
    if not 'value' in request.form:
        return _error_internal('No value')
    vendor.restrictions.append(Restriction(request.form['value']))
    db.session.commit()
    flash('Added restriction', 'info')
    return redirect(url_for('.vendor_restrictions', vendor_id=vendor_id), 302)

@app.route('/lvfs/vendor/<int:vendor_id>/restriction/<int:restriction_id>/delete')
@login_required
def vendor_restriction_delete(vendor_id, restriction_id):
    """ Allows changing a vendor [ADMIN ONLY] """

    # security check
    if not g.user.check_capability(UserCapability.Admin):
        return _error_permission_denied('Unable to edit vendor as non-admin')
    vendor = db.session.query(Vendor).filter(Vendor.vendor_id == vendor_id).first()
    if not vendor:
        flash('Failed to get vendor details: No a vendor with that group ID', 'warning')
        return redirect(url_for('.vendor_list'), 302)
    for res in vendor.restrictions:
        if res.restriction_id == restriction_id:
            db.session.delete(res)
            db.session.commit()
            break
    flash('Deleted restriction', 'info')
    return redirect(url_for('.vendor_restrictions', vendor_id=vendor_id), 302)

@app.route('/lvfs/vendor/<int:vendor_id>/modify_by_admin', methods=['GET', 'POST'])
@login_required
def vendor_modify_by_admin(vendor_id):
    """ Change details about the any vendor """

    # only accept form data
    if request.method != 'POST':
        return redirect(url_for('.vendor_list'))

    # security check
    if not g.user.check_capability(UserCapability.Admin):
        return _error_permission_denied('Unable to modify vendor as non-admin')

    # save to database
    vendor = db.session.query(Vendor).filter(Vendor.vendor_id == vendor_id).first()
    if not vendor:
        flash('Failed to modify vendor: No a vendor with that group ID', 'warning')
        return redirect(url_for('.vendor_list'), 302)
    for key in ['display_name',
                'plugins',
                'description',
                'visible',
                'visible_for_search',
                'is_fwupd_supported',
                'is_account_holder',
                'is_uploading',
                'comments',
                'keywords']:
        if key in request.form:
            setattr(vendor, key, request.form[key])
    db.session.commit()
    flash('Updated vendor', 'info')
    return redirect(url_for('.vendor_list'))

@app.route('/lvfs/vendor/<int:vendor_id>/upload', methods=['POST'])
@login_required
def vendor_upload(vendor_id):

    # security check
    if not g.user.check_capability(UserCapability.Admin):
        return _error_permission_denied('Unable to modify vendor as non-admin')

    # check exists
    vendor = db.session.query(Vendor).filter(Vendor.vendor_id == vendor_id).first()
    if not vendor:
        flash('Failed to modify vendor: No a vendor with that group ID', 'warning')
        return redirect(url_for('.vendor_list'), 302)

    # not correct parameters
    if not 'file' in request.files:
        return _error_internal('No file')

    # write the pixmap
    buf = request.files['file'].read()
    fn = os.path.join(app.config['UPLOAD_DIR'], 'vendor-%s.png' % vendor_id)
    open(fn, 'wb').write(buf)

    vendor.icon = os.path.basename(fn)
    db.session.commit()
    flash('Modified vendor', 'info')

    return redirect(url_for('.vendor_details', vendor_id=vendor_id), 302)
