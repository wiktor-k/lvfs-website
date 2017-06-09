#!/usr/bin/python2
# -*- coding: utf-8 -*-
#
# Copyright (C) 2015-2017 Richard Hughes <richard@hughsie.com>
# Licensed under the GNU General Public License Version 2

import os

from flask import Flask, flash, render_template
from flask.ext.login import LoginManager

from .db import Database

app = Flask(__name__)
if 'OPENSHIFT_PYTHON_DIR' in os.environ:
    app.config.from_pyfile('openshift.cfg')
else:
    app.config.from_pyfile('flaskapp.cfg')

lm = LoginManager()
lm.init_app(app)

db = Database(app)
db.verify()

@lm.user_loader
def load_user(user_id):
    user = db.users.get_item(user_id)
    return user

@app.errorhandler(404)
def error_page_not_found(msg=None):
    """ Error handler: File not found """
    flash(msg)
    return render_template('error.html'), 404

from app import views
from app import views_user
from app import views_group
from app import views_device
