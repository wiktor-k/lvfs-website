#!/usr/bin/python2
# -*- coding: utf-8 -*-
#
# Copyright (C) 2017 Richard Hughes <richard@hughsie.com>
# Licensed under the GNU General Public License Version 2

from flask import request, flash, url_for, redirect, render_template, g
from flask_login import login_required

from app import app, db

from .util import _error_internal, _error_permission_denied
from .models import UserCapability, User, Vendor
from .hash import _password_hash

def _password_check(value):
    """ Check the password for suitability """
    success = True
    if len(value) < 8:
        success = False
        flash('The password is too short, the minimum is 8 characters', 'warning')
    if len(value) > 40:
        success = False
        flash('The password is too long, the maximum is 40 characters', 'warning')
    if value.lower() == value:
        success = False
        flash('The password requires at least one uppercase character', 'warning')
    if value.isalnum():
        success = False
        flash('The password requires at least one non-alphanumeric character', 'warning')
    return success

def _email_check(value):
    """ Do a quick and dirty check on the email address """
    if len(value) < 5 or value.find('@') == -1 or value.find('.') == -1:
        return False
    return True

@app.route('/lvfs/user/<int:user_id>/modify', methods=['GET', 'POST'])
@login_required
def user_modify(user_id):
    """ Change details about the current user """

    # only accept form data
    if request.method != 'POST':
        return redirect(url_for('.profile'))

    # security check
    if g.user.user_id != user_id:
        return _error_permission_denied('Unable to modify a different user')
    if g.user.is_locked:
        return _error_permission_denied('Unable to change user as account locked')

    # check we got enough data
    if not 'password_new' in request.form:
        return _error_permission_denied('Unable to change user as no data')
    if not 'password_old' in request.form:
        return _error_permission_denied('Unable to change user as no data')
    if not 'name' in request.form:
        return _error_permission_denied('Unable to change user as no data')
    if not 'email' in request.form:
        return _error_permission_denied('Unable to change user as no data')
    old_password_hash = _password_hash(request.form['password_old'])
    user = db.session.query(User).\
            filter(User.user_id == user_id).\
            filter(User.password == old_password_hash).first()
    if not user:
        flash('Failed to modify profile: Incorrect existing password', 'danger')
        return redirect(url_for('.profile'), 302)

    # check password
    password = request.form['password_new']
    if not _password_check(password):
        return redirect(url_for('.profile'), 302)

    # check email
    email = request.form['email']
    if not _email_check(email):
        flash('Failed to modify profile: Invalid email address', 'warning')
        return redirect(url_for('.profile'))

    # verify name
    name = request.form['name']
    if len(name) < 3:
        flash('Failed to modify profile: Name invalid', 'warning')
        return redirect(url_for('.profile'), 302)

    # save to database
    user.password = _password_hash(password)
    user.display_name = name
    user.email = email
    db.session.commit()
    flash('Updated profile', 'info')
    return redirect(url_for('.profile'))

@app.route('/lvfs/user/<int:user_id>/modify_by_admin', methods=['POST'])
@login_required
def user_modify_by_admin(user_id):
    """ Change details about the any user """

    # security check
    if not g.user.check_capability(UserCapability.Admin):
        return _error_permission_denied('Unable to modify user as non-admin')

    # get user
    user = db.session.query(User).filter(User.user_id == user_id).first()
    if not user:
        return _error_internal('No user with that user_id', 422)

    # set each optional thing in turn
    for key in ['display_name', 'email']:
        if key in request.form:
            setattr(user, key, request.form[key])

    # unchecked checkbuttons are not included in the form data
    for key in ['is_enabled', 'is_qa', 'is_analyst', 'is_locked']:
        setattr(user, key, True if key in request.form else False)

    # password is optional, and hashed
    if 'password' in request.form and request.form['password']:
        user.password = _password_hash(request.form['password'])

    db.session.commit()
    flash('Updated profile', 'info')
    return redirect(url_for('.user_admin', user_id=user_id))

@app.route('/lvfs/user/add', methods=['GET', 'POST'])
@login_required
def user_add():
    """ Add a user [ADMIN ONLY] """

    # only accept form data
    if request.method != 'POST':
        return redirect(url_for('.profile'))

    # security check
    if not g.user.check_capability(UserCapability.Admin):
        return _error_permission_denied('Unable to add user as non-admin')

    if not 'password_new' in request.form:
        return _error_permission_denied('Unable to add user as no password_new')
    if not 'username_new' in request.form:
        return _error_permission_denied('Unable to add user as no username_new')
    if not 'group_id' in request.form:
        return _error_permission_denied('Unable to add user as no group_id')
    if not 'name' in request.form:
        return _error_permission_denied('Unable to add user as no name')
    if not 'email' in request.form:
        return _error_permission_denied('Unable to add user as no email')
    user = db.session.query(User).filter(User.username == request.form['username_new']).first()
    if user:
        return _error_internal('Already a entry with that username', 422)

    # verify password
    password = request.form['password_new']
    if not _password_check(password):
        return redirect(url_for('.user_list'), 302)

    # verify email
    email = request.form['email']
    if not _email_check(email):
        flash('Failed to add user: Invalid email address', 'warning')
        return redirect(url_for('.user_list'), 302)

    # verify group_id
    group_id = request.form['group_id']
    if len(group_id) < 3:
        flash('Failed to add user: QA group invalid', 'warning')
        return redirect(url_for('.user_list'), 302)

    # verify name
    name = request.form['name']
    if len(name) < 3:
        flash('Failed to add user: Name invalid', 'warning')
        return redirect(url_for('.user_list'), 302)

    # verify username
    username_new = request.form['username_new']
    if len(username_new) < 3:
        flash('Failed to add user: Username invalid', 'warning')
        return redirect(url_for('.user_list'), 302)

    vendor = db.session.query(Vendor).filter(Vendor.group_id == group_id).first()
    if not vendor:
        vendor = Vendor(group_id)
        db.session.add(vendor)
        db.session.commit()
    user = User(username=username_new,
                password=_password_hash(password),
                display_name=name,
                email=email,
                vendor_id=vendor.vendor_id)
    db.session.add(user)
    db.session.commit()
    flash('Added user %i' % user.user_id, 'info')
    return redirect(url_for('.user_list'), 302)

@app.route('/lvfs/user/<int:user_id>/delete')
@login_required
def user_delete(user_id):
    """ Delete a user """

    # security check
    if not g.user.check_capability(UserCapability.Admin):
        return _error_permission_denied('Unable to remove user as not admin')

    # check whether exists in database
    user = db.session.query(User).filter(User.user_id == user_id).first()
    if not user:
        flash('Failed to delete user: No user found', 'danger')
        return redirect(url_for('.user_list'), 422)
    db.session.delete(user)
    db.session.commit()
    flash('Deleted user', 'info')
    return redirect(url_for('.user_list'), 302)

@app.route('/lvfs/userlist')
@login_required
def user_list():
    """
    Show a list of all users
    """
    if not g.user.check_capability(UserCapability.Admin):
        return _error_permission_denied('Unable to show userlist for non-admin user')
    return render_template('userlist.html', users=db.session.query(User).all())

@app.route('/lvfs/user/<int:user_id>/admin')
@login_required
def user_admin(user_id):
    """
    Shows an admin panel for a user
    """
    if not g.user.check_capability(UserCapability.Admin):
        return _error_permission_denied('Unable to modify user for non-admin user')
    user = db.session.query(User).filter(User.user_id == user_id).first()
    if not user:
        flash('No user found', 'danger')
        return redirect(url_for('.user_list'), 422)
    return render_template('useradmin.html', u=user)
