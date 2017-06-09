#!/usr/bin/python2
# -*- coding: utf-8 -*-
#
# Copyright (C) 2017 Richard Hughes <richard@hughsie.com>
# Licensed under the GNU General Public License Version 2

from flask import session, request, flash, url_for, redirect, render_template
from flask.ext.login import login_required

from app import app, db

from .util import _event_log, _error_internal, _error_permission_denied
from .db import CursorError

def _password_check(value):
    """ Check the password for suitability """
    success = True
    if len(value) < 8:
        success = False
        flash('The password is too short, the minimum is 8 characters')
    if len(value) > 40:
        success = False
        flash('The password is too long, the maximum is 40 characters')
    if value.lower() == value:
        success = False
        flash('The password requires at least one uppercase character')
    if value.isalnum():
        success = False
        flash('The password requires at least one non-alphanumeric character')
    return success

def _email_check(value):
    """ Do a quick and dirty check on the email address """
    if len(value) < 5 or value.find('@') == -1 or value.find('.') == -1:
        flash('Invalid email address')
        return False
    return True

@app.route('/lvfs/user/<username>/modify', methods=['GET', 'POST'])
@login_required
def user_modify(username):
    """ Change details about the current user """

    # only accept form data
    if request.method != 'POST':
        return redirect(url_for('.profile'))

    # security check
    if session['username'] != username:
        return _error_permission_denied('Unable to modify a different user')
    if session['is_locked']:
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
    try:
        auth = db.users.verify(session['username'], request.form['password_old'])
    except CursorError as e:
        return _error_internal(str(e))
    if not auth:
        return _error_internal('Incorrect existing password')

    # check password
    password = request.form['password_new']
    if not _password_check(password):
        return redirect(url_for('.profile')), 400

    # check email
    email = request.form['email']
    if not _email_check(email):
        return redirect(url_for('.profile'))

    # check pubkey
    pubkey = ''
    if 'pubkey' in request.form:
        pubkey = request.form['pubkey']
        if pubkey:
            if len(pubkey) > 0:
                if not pubkey.startswith("-----BEGIN PGP PUBLIC KEY BLOCK-----"):
                    flash('Invalid GPG public key')
                    return redirect(url_for('.profile')), 400

    # verify name
    name = request.form['name']
    if len(name) < 3:
        flash('Name invalid')
        return redirect(url_for('.profile')), 400
    try:
        db.users.update(session['username'], password, name, email, pubkey)
    except CursorError as e:
        return _error_internal(str(e))
    #session['password'] = _password_hash(password)
    _event_log('Changed password')
    flash('Updated profile')
    return redirect(url_for('.profile'))

@app.route('/lvfs/user/<username>/modify_by_admin', methods=['POST'])
@login_required
def user_modify_by_admin(username):
    """ Change details about the any user """

    # security check
    if session['username'] != 'admin':
        return _error_permission_denied('Unable to modify user as non-admin')

    # set each thing in turn
    for key in ['qa_group',
                'display_name',
                'email',
                'password',
                'is_enabled',
                'is_qa',
                'is_locked',
                'pubkey']:
        # unchecked checkbuttons are not included in the form data
        if key in request.form:
            tmp = request.form[key]
        else:
            tmp = '0'
        try:
            # don't set the optional password
            if key == 'password' and len(tmp) == 0:
                continue
            db.users.set_property(username, key, tmp)
        except CursorError as e:
            return _error_internal(str(e))
    _event_log('Changed user %s properties' % username)
    flash('Updated profile')
    return redirect(url_for('.user_admin', user_name=username))

@app.route('/lvfs/user/add', methods=['GET', 'POST'])
@login_required
def user_add():
    """ Add a user [ADMIN ONLY] """

    # only accept form data
    if request.method != 'POST':
        return redirect(url_for('.profile'))

    # security check
    if session['username'] != 'admin':
        return _error_permission_denied('Unable to add user as non-admin')

    if not 'password_new' in request.form:
        return _error_permission_denied('Unable to add user an no data')
    if not 'username_new' in request.form:
        return _error_permission_denied('Unable to add user an no data')
    if not 'qa_group' in request.form:
        return _error_permission_denied('Unable to add user an no data')
    if not 'name' in request.form:
        return _error_permission_denied('Unable to add user an no data')
    if not 'email' in request.form:
        return _error_permission_denied('Unable to add user an no data')
    try:
        auth = db.users.is_enabled(request.form['username_new'])
    except CursorError as e:
        return _error_internal(str(e))
    if auth:
        return _error_internal('Already a entry with that username', 422)

    # verify password
    password = request.form['password_new']
    if not _password_check(password):
        return redirect(url_for('.user_list')), 302

    # verify email
    email = request.form['email']
    if not _email_check(email):
        return redirect(url_for('.user_list')), 302

    # verify qa_group
    qa_group = request.form['qa_group']
    if len(qa_group) < 3:
        flash('QA group invalid')
        return redirect(url_for('.user_list')), 302

    # verify name
    name = request.form['name']
    if len(name) < 3:
        flash('Name invalid')
        return redirect(url_for('.user_list')), 302

    # verify username
    username_new = request.form['username_new']
    if len(username_new) < 3:
        flash('Username invalid')
        return redirect(url_for('.user_list')), 302
    try:
        db.users.add(username_new, password, name, email, qa_group)
        if not db.groups.get_item(qa_group):
            db.groups.add(qa_group)
    except CursorError as e:
        return _error_internal(str(e))

    _event_log("Created user %s" % username_new)
    flash('Added user')
    return redirect(url_for('.user_list')), 201

@app.route('/lvfs/user/<username>/delete')
@login_required
def user_delete(username):
    """ Delete a user """

    # security check
    if session['username'] != 'admin':
        return _error_permission_denied('Unable to remove user as not admin')

    # check whether exists in database
    try:
        exists = db.users.is_enabled(username)
    except CursorError as e:
        return _error_internal(str(e))
    if not exists:
        flash("No entry with username %s" % username)
        return redirect(url_for('.user_list')), 400
    try:
        db.users.remove(username)
    except CursorError as e:
        return _error_internal(str(e))
    _event_log("Deleted user %s" % username)
    flash('Deleted user')
    return redirect(url_for('.user_list')), 201

@app.route('/lvfs/userlist')
@login_required
def user_list():
    """
    Show a list of all users
    """
    if session['username'] != 'admin':
        return _error_permission_denied('Unable to show userlist for non-admin user')
    try:
        items = db.users.get_all()
    except CursorError as e:
        return _error_internal(str(e))
    return render_template('userlist.html', users=items)

@app.route('/lvfs/user/<user_name>/admin')
@login_required
def user_admin(user_name):
    """
    Shows an admin panel for a user
    """
    if session['username'] != 'admin':
        return _error_permission_denied('Unable to modify user for non-admin user')
    try:
        item = db.users.get_item(user_name)
    except CursorError as e:
        return _error_internal(str(e))
    return render_template('useradmin.html', u=item)
