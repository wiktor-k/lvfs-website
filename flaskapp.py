#!/usr/bin/python2
# -*- coding: utf-8 -*-
#
# Copyright (C) 2015-2016 Richard Hughes <richard@hughsie.com>
# Licensed under the GNU General Public License Version 2

import os
import datetime

from flask import Flask, flash, render_template, redirect, request, send_from_directory, abort
from flask.ext.login import LoginManager

from db import LvfsDatabase, CursorError
from db_clients import LvfsDatabaseClients, LvfsDownloadKind
from db_users import LvfsDatabaseUsers
from config import CDN_URI

def _get_client_address():
    """ Gets user IP address """
    if request.headers.getlist("X-Forwarded-For"):
        return request.headers.getlist("X-Forwarded-For")[0]
    else:
        return request.remote_addr

################################################################################

from lvfs import lvfs

app = Flask(__name__)
app.config.from_pyfile('flaskapp.cfg')
app.register_blueprint(lvfs)

login_manager = LoginManager()
login_manager.init_app(app)

@login_manager.user_loader
def load_user(user_id):
    db = LvfsDatabase(os.environ)
    db_users = LvfsDatabaseUsers(db)
    user = db_users.get_item(user_id)
    return user

@app.errorhandler(404)
def error_page_not_found(msg=None):
    """ Error handler: File not found """
    flash(msg)
    return render_template('error.html'), 404

@app.route('/<path:resource>')
def serveStaticResource(resource):
    """ Return a static image or resource """

    # ban MJ12BOT, it ignores robots.txt
    user_agent = request.headers.get('User-Agent')
    if user_agent and user_agent.find('MJ12BOT') != -1:
        abort(403)

    # log certain kinds of files
    if resource.endswith('.cab'):
        try:
            db = LvfsDatabase(os.environ)
            clients = LvfsDatabaseClients(db)
            clients.log(datetime.date.today(), LvfsDownloadKind.FIRMWARE)
            clients.increment(_get_client_address(),
                              os.path.basename(resource),
                              user_agent)
        except CursorError as e:
            print str(e)

    # firmware blobs are stored on S3 now
    if resource.startswith('downloads/'):
        return redirect(os.path.join(CDN_URI, resource), 301)

    # static files served locally
    return send_from_directory('static/', resource)

if __name__ == '__main__':
    if not 'OPENSHIFT_APP_DNS' in os.environ:
        app.debug = True
    app.run()
