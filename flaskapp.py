#!/usr/bin/python2
# -*- coding: utf-8 -*-
#
# Copyright (C) 2015 Richard Hughes <richard@hughsie.com>
# Licensed under the GNU General Public License Version 2

import os
from flask import Flask, flash, render_template, redirect, request, send_from_directory

from db import LvfsDatabase, CursorError
from db_clients import LvfsDatabaseClients, LvfsDownloadKind

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

################################################################################

@app.errorhandler(404)
def error_page_not_found(msg=None):
    """ Error handler: File not found """
    flash(msg)
    return render_template('error.html'), 404

@app.route('/')
def fwupd_index():
    """ Main fwupd.org site """
    return render_template('fwupd/index.html')

@app.route('/users')
def fwupd_users():
    """ User-centric fwupd help """
    return render_template('fwupd/users.html')

@app.route('/developers')
def fwupd_developers():
    """ Developer-centric fwupd help """
    return render_template('fwupd/developers.html')

@app.route('/vendors')
def fwupd_vendors():
    """ Vendor-centric fwupd help """
    return render_template('fwupd/vendors.html')

################################################################################

@app.route('/<path:resource>')
def serveStaticResource(resource):
    """ Return a static image or resource """

    # log certain kinds of files
    kind = None
    if resource.endswith('.cab'):
        kind = LvfsDownloadKind.FIRMWARE
    elif resource.endswith('.xml.gz.asc'):
        kind = LvfsDownloadKind.SIGNING
    elif resource.endswith('.xml.gz'):
        kind = LvfsDownloadKind.METADATA
    if kind is not None:
        try:
            filename = os.path.basename(resource)
            db = LvfsDatabase(os.environ)
            clients = LvfsDatabaseClients(db)
            clients.increment(_get_client_address(),
                              kind,
                              filename,
                              request.headers.get('User-Agent'))
        except CursorError as e:
            print str(e)

    # use apache for the static file so we can scale
    if 'OPENSHIFT_APP_DNS' in os.environ:
        if resource.startswith('download/'):
            uri = "https://%s/static/%s" % (os.environ['OPENSHIFT_APP_DNS'], resource)
            return redirect(uri, 301)

    return send_from_directory('static/', resource)

if __name__ == '__main__':
    if not 'OPENSHIFT_APP_DNS' in os.environ:
        app.debug = True
    app.run()
