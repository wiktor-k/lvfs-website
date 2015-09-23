#!/usr/bin/python
# -*- coding: utf-8 -*-
#
# Copyright (C) 2015 Richard Hughes <richard@hughsie.com>
# Licensed under the GNU General Public License Version 2
import os

STATIC_DIR = 'static'
UPLOAD_DIR = 'uploads'
DOWNLOAD_DIR = 'downloads'
KEYRING_DIR = 'gnupg'
CABEXTRACT_CMD = '/usr/bin/cabextract'
if 'OPENSHIFT_PYTHON_DIR' in os.environ:
    virtenv = os.environ['OPENSHIFT_PYTHON_DIR'] + '/virtenv/'
    virtualenv = os.path.join(virtenv, 'bin/activate_this.py')
    try:
        execfile(virtualenv, dict(__file__=virtualenv))
    except IOError:
        pass
    STATIC_DIR = os.path.join(os.environ['OPENSHIFT_REPO_DIR'], 'static')
    UPLOAD_DIR = os.path.join(os.environ['OPENSHIFT_DATA_DIR'], 'uploads')
    DOWNLOAD_DIR = os.path.join(os.environ['OPENSHIFT_DATA_DIR'], 'downloads')
    KEYRING_DIR = os.path.join(os.environ['OPENSHIFT_DATA_DIR'], 'gnupg')

    # this needs to be setup using:
    # cd app-root/data/
    # wget http://www.cabextract.org.uk/cabextract-1.6.tar.gz
    # tar xvfz cabextract-1.6.tar.gz
    # cd cabextract-1.6 && ./configure --prefix=/tmp && make
    # rm cabextract-1.6.tar.gz
    CABEXTRACT_CMD = os.path.join(os.environ['OPENSHIFT_DATA_DIR'],
                                  'cabextract-1.6',
                                  'cabextract')

from wsgiref.simple_server import make_server
from Cookie import SimpleCookie
import locale
import cgi
import hashlib
import math
import glob
import calendar
import datetime
import ConfigParser

import cabarchive
import appstream
from affidavit import Affidavit, NoKeyError
from db import LvfsDatabase, CursorError
from db_users import _password_hash
from db_firmware import LvfsFirmware
from inf_parser import InfParser

def _qa_hash(value):
    """ Generate a salted hash of the QA group """
    salt = 'vendor%%%'
    return hashlib.sha1(salt + value).hexdigest()

def _password_check(value):
    """ Check the password for suitability """
    if len(value) < 8:
        return 'The password is too short, the minimum is 8 character'
    if len(value) > 40:
        return 'The password is too long, the maximum is 40 character'
    if value.lower() == value:
        return 'The password requires at least one uppercase character'
    if value.isalnum():
        return 'The password requires at least one non-alphanumeric character'
    return None

def _email_check(value):
    """ Do a quick and dirty check on the email address """
    if len(value) < 5 or value.find('@') == -1 or value.find('.') == -1:
        return 'Invalid email address'
    return None

def _get_chart_labels_months():
    """ Gets the chart labels """
    now = datetime.date.today()
    labels = []
    offset = 0
    for i in range(0, 12):
        if now.month - i == 0:
            offset = 1
        labels.append(calendar.month_name[now.month - i - offset])
    return labels

def _get_chart_labels_days():
    """ Gets the chart labels """
    now = datetime.date.today()
    labels = []
    for i in range(0, 30):
        then = now - datetime.timedelta(i)
        labels.append("%02i-%02i-%02i" % (then.year, then.month, then.day))
    return labels

def _get_chart_labels_hours():
    """ Gets the chart labels """
    labels = []
    for i in range(0, 24):
        labels.append("%02i" % i)
    return labels

class LvfsWebsite(object):
    """ A helper class """

    def __init__(self):
        """ Ininitalize the object """
        self.username = ''
        self.password = '' # hashed
        self.qa_group = ''
        self.qa_capability = False
        self.is_locked = False
        self.fields = None
        self.qs_get = None
        self._is_login_from_post = False
        self._db = None
        self.client_address = None
        self.session_cookie = SimpleCookie()
        self.response_code = None
        self.content_type = 'text/html'

    def _event_log(self, msg, username=None, is_important=False):
        """ Adds an item to the event log """
        if not username:
            username = self.username
        self._db.eventlog.add(msg, username, self.client_address, is_important)

    def create_affidavit(self):
        """ Create an affidavit that can be used to sign files """
        key_uid = self._db.users.get_signing_uid()
        return Affidavit(key_uid, KEYRING_DIR)

    def _set_response_code(self, rc):
        """ Set the response code if not already set """
        if self.response_code:
            return
        self.response_code = rc

    def _gen_header(self, title, show_navigation=True):
        """ Generate a HTML header for all pages """
        html = """
<!DOCTYPE html>
<!-- Copyright (C) 2015 Richard Hughes <richard@hughsie.com>
     Licensed under the GNU General Public License Version 2 -->
<html>
<head>
<title>LVFS: %s</title>
<meta http-equiv="Content-Type" content="text/html;charset=utf-8"/>
<link rel="stylesheet" href="style.css" type="text/css" media="screen"/>
<link rel="shortcut icon" href="favicon.ico"/>
</head>
<body>
"""
        html = html % title

        # add navigation
        if show_navigation:
            html += '<ul class="navigation">\n'
            html += '  <li class="navigation"><a class="navigation" href="?">Home</a></li>\n'
            html += '  <li class="navigation"><a class="navigation" href="?action=existing">Firmware</a></li>\n'
            html += '  <li class="navigation"><a class="navigation" href="?action=metadata">Metadata</a></li>\n'
            if self.username == 'admin':
                html += '  <li class="navigation"><a class="navigation" href="?action=userlist">Users</a></li>\n'
                html += '  <li class="navigation"><a class="navigation" href="?action=eventlog">Event Log</a></li>\n'
                html += '  <li class="navigation"><a class="navigation" href="?action=analytics">Analytics</a></li>\n'
            html += '  <li class="navigation2"><a class="navigation" href="?action=logout">Log Out</a></li>\n'
            if not self.is_locked:
                html += '  <li class="navigation2"><a class="navigation" href="?action=profile">Profile</a></li>\n'
            html += '</ul>\n'

        return html

    def _gen_footer(self):
        """ Generate a footer at the bottom of the page """
        html = """
<p class="footer">
 Copyright <a href="mailto:richard@hughsie.com">Richard Hughes 2015</a>
</p>
</body>
</html>
"""
        return html

    def _action_newaccount(self):
        html = """
<h1>Applying for a new account</h1>
<p>
 Vendors who can submit automatic firmware updates are in a privileged position where files
 can be installed on user systems without authentication.
 This means we have to do careful checks on vendors, and it's important
 for vendors to understand the ramifications of getting it wrong.
</p>
<p>
 The Linux Vendor Firmware Project signs the firmware image and repacks
 the files into a new cabinet file for several reasons:
</p>
<ul>
 <li>
  Only trusted vendors have access to the LVFS service, so we can be
  sure the firmware actually came from the vendor.
 </li>
 <li>
  Clients do not (yet) verify the signatures in the catalog file.
 </li>
 <li>
  Not all software trusts the Microsoft WHQL certificate.
 </li>
 <li>
  Only required files are included in the compressed cabinet file,
  typically making the download size much smaller.
 </li>
</ul>

<p>
 When creating an account we can optionally create two classes of user,
 which allows you to have your firmware engineers do the upload and QA users
 control who can access the firmware:
</p>
<ul>
 <li>Unprivileged users can upload files to the private target</li>
 <li>QA users can move the firmware from Private &#8594; Embargoed &#8594; Testing &#8594; Stable</li>
</ul>
<p>
 We can create as many different users of each type as required, and
 each can have a different password.
 Some vendors just need one 'QA User' as the person uploading the
 firmware is also the person who decides when to move the update from
 testing to stable.
</p>

<p>
 If you would like to know more, or want to request a new account,
 please <a href="mailto:richard@hughsie.com">email me</a> for more details.
</p>
"""
        self._set_response_code('200 OK')
        return self._gen_header('New Account', show_navigation=False) + html + self._gen_footer()

    def _action_login(self, error_msg=None):
        """ A login screen to allow access to the LVFS main page """

        html = """
<h1 class="banner">Linux Vendor<br>Firmware Service</h1>
<h2>Please Login</h2>
<p>%s</p>
<p>
The Linux Vendor Firmware Service is a secure portal which allows
hardware vendors to upload firmware updates.
Files can be uploaded privately and optionally embargoed until a specific date.
</p>
<p>
This site is used by all major Linux distributions to provide metadata
for clients such as fwupdmgr and GNOME Software.
In the last month we've provided %s firmware files to %s unique users.
To upload firmware please login, or <a href="?action=newaccount">request a new account</a>.
</p>
<form method="post" action="wsgi.py">
<table class="upload">
<tr>
<th class="upload"><label for="username">Username:</label></td>
<td><input type="text" name="username" required></td>
</tr>
<tr>
<th class="upload"><label for="password">Password:</label></td>
<td><input type="password" name="password" required></td>
</tr>
</table>
<input type="submit" class="submit" value="Login">
</form>
</body>
</html>
"""
        # get the number of files we've provided
        locale.setlocale(locale.LC_ALL, 'en_US')
        download_str = locale.format("%d", self._db.firmware.get_download_cnt(), grouping=True)
        user_str = locale.format("%d", self._db.clients.get_firmware_count_unique(), grouping=True)
        if error_msg:
            html = html % (error_msg, download_str, user_str)
        else:
            html = html % ('', download_str, user_str)

        # set correct response code
        self._set_response_code('401 Unauthorized')
        return self._gen_header('Login', show_navigation=False) + html + self._gen_footer()

    def _action_analytics(self):
        """ A analytics screen to show information about users """

        # admin only
        if self.username != 'admin':
            return self._action_permission_denied('Unable to view analytics')

        # load external resource
        html = '<script src="Chart.js"></script>'
        html += '<h1>Analytics</h1>'

        # add days
        data_md = self._db.clients.get_metadata_stats(30, 1)
        data_fw = self._db.clients.get_firmware_stats(30, 1)
        html += '<h2>Metadata and Firmware Downloads (day)</h2>'
        html += '<canvas id="metadataChartMonthsDays" width="800" height="400"></canvas>'
        html += '<script>'
        html += 'var ctx = document.getElementById("metadataChartMonthsDays").getContext("2d");'
        html += 'var data = {'
        html += '    labels: %s,' % _get_chart_labels_days()[::-1]
        html += '    datasets: ['
        html += '        {'
        html += '            label: "Metadata",'
        html += '            fillColor: "rgba(20,120,220,0.2)",'
        html += '            strokeColor: "rgba(20,120,120,0.1)",'
        html += '            pointColor: "rgba(20,120,120,0.3)",'
        html += '            pointStrokeColor: "#fff",'
        html += '            pointHighlightFill: "#fff",'
        html += '            pointHighlightStroke: "rgba(220,220,220,1)",'
        html += '            data: %s' % data_md[::-1]
        html += '        },'
        html += '        {'
        html += '            label: "Firmware",'
        html += '            fillColor: "rgba(251,14,5,0.2)",'
        html += '            strokeColor: "rgba(151,14,5,0.1)",'
        html += '            pointColor: "rgba(151,14,5,0.3)",'
        html += '            pointStrokeColor: "#fff",'
        html += '            pointHighlightFill: "#fff",'
        html += '            pointHighlightStroke: "rgba(151,187,205,1)",'
        html += '            data: %s' % data_fw[::-1]
        html += '        },'
        html += '    ]'
        html += '};'
        html += 'var myLineChartDays = new Chart(ctx).Line(data, null);'
        html += '</script>'

        # add months
        data_md = self._db.clients.get_metadata_stats(12, 30)
        data_fw = self._db.clients.get_firmware_stats(12, 30)
        html += '<h2>Metadata and Firmware Downloads (month)</h2>'
        html += '<canvas id="metadataChartMonths" width="800" height="400"></canvas>'
        html += '<script>'
        html += 'var ctx = document.getElementById("metadataChartMonths").getContext("2d");'
        html += 'var data = {'
        html += '    labels: %s,' % _get_chart_labels_months()[::-1]
        html += '    datasets: ['
        html += '        {'
        html += '            label: "Metadata",'
        html += '            fillColor: "rgba(20,120,220,0.2)",'
        html += '            strokeColor: "rgba(20,120,120,0.1)",'
        html += '            pointColor: "rgba(20,120,120,0.3)",'
        html += '            pointStrokeColor: "#fff",'
        html += '            pointHighlightFill: "#fff",'
        html += '            pointHighlightStroke: "rgba(220,220,220,1)",'
        html += '            data: %s' % data_md[::-1]
        html += '        },'
        html += '        {'
        html += '            label: "Firmware",'
        html += '            fillColor: "rgba(251,14,5,0.2)",'
        html += '            strokeColor: "rgba(151,14,5,0.1)",'
        html += '            pointColor: "rgba(151,14,5,0.3)",'
        html += '            pointStrokeColor: "#fff",'
        html += '            pointHighlightFill: "#fff",'
        html += '            pointHighlightStroke: "rgba(151,187,205,1)",'
        html += '            data: %s' % data_fw[::-1]
        html += '        },'
        html += '    ]'
        html += '};'
        html += 'var myLineChartMonths = new Chart(ctx).Line(data, null);'
        html += '</script>'

        # add hours
        data_md = self._db.clients.get_metadata_by_hour()
        html += '<h2>Metadata and Firmware Downloads (hour)</h2>'
        html += '<canvas id="metadataChartHours" width="800" height="400"></canvas>'
        html += '<script>'
        html += 'var ctx = document.getElementById("metadataChartHours").getContext("2d");'
        html += 'var data = {'
        html += '    labels: %s,' % _get_chart_labels_hours()
        html += '    datasets: ['
        html += '        {'
        html += '            label: "Metadata",'
        html += '            fillColor: "rgba(20,120,220,0.2)",'
        html += '            strokeColor: "rgba(20,120,120,0.1)",'
        html += '            pointColor: "rgba(20,120,120,0.3)",'
        html += '            pointStrokeColor: "#fff",'
        html += '            pointHighlightFill: "#fff",'
        html += '            pointHighlightStroke: "rgba(220,220,220,1)",'
        html += '            data: %s' % data_md
        html += '        },'
        html += '    ]'
        html += '};'
        html += 'var myLineChartHours = new Chart(ctx).Line(data, null);'
        html += '</script>'

        # set correct response code
        self._set_response_code('200 OK')
        return self._gen_header('Analytics') + html + self._gen_footer()

    def _action_useradd(self):
        """ Add a user [ADMIN ONLY] """

        if self.username != 'admin':
            return self._action_permission_denied('Unable to add user as non-admin')
        if not 'password_new' in self.fields:
            return self._action_permission_denied('Unable to add user an no data')
        if not 'username_new' in self.fields:
            return self._action_permission_denied('Unable to add user an no data')
        if not 'qa_group' in self.fields:
            return self._action_permission_denied('Unable to add user an no data')
        if not 'name' in self.fields:
            return self._action_permission_denied('Unable to add user an no data')
        if not 'email' in self.fields:
            return self._action_permission_denied('Unable to add user an no data')
        try:
            auth = self._db.users.is_enabled(self.fields['username_new'].value)
        except CursorError as e:
            return self._internal_error(str(e))
        if auth:
            self._set_response_code('422 Entity Already Exists')
            return self._action_userlist('Already a entry with that username')

        # verify password
        password = self.fields['password_new'].value
        pw_check = _password_check(password)
        if pw_check:
            self._set_response_code('400 Bad Request')
            return self._action_userlist(pw_check)

        # verify email
        email = self.fields['email'].value
        email_check = _email_check(email)
        if email_check:
            self._set_response_code('400 Bad Request')
            return self._action_userlist(email_check)

        # verify qa_group
        qa_group = self.fields['qa_group'].value
        if len(qa_group) < 3:
            self._set_response_code('400 Bad Request')
            return self._action_userlist('QA group invalid')

        # verify name
        name = self.fields['name'].value
        if len(name) < 3:
            self._set_response_code('400 Bad Request')
            return self._action_userlist('Name invalid')

        # verify username
        username_new = self.fields['username_new'].value
        if len(username_new) < 3:
            self._set_response_code('400 Bad Request')
            return self._action_userlist('Username invalid')
        try:
            self._db.users.add(username_new, password, name, email, qa_group)
        except CursorError as e:
            #FIXME
            pass

        self._event_log("Created user %s" % username_new)
        self._set_response_code('201 Created')
        return self._action_userlist('Added user')

    def _action_userinc(self, value):
        """ Adds or remove a capability to a user """

        # check admin
        if self.username != 'admin':
            return self._action_permission_denied('Unable to inc user as not admin')
        username_new = self.qs_get.get('username_new', [None])[0]
        if not username_new:
            return self._action_permission_denied('Unable to inc user as no data')

        # get modification type
        key = self.qs_get.get('key', [None])[0]
        if not key:
            return self._action_permission_denied('Unable to inc user as no data')

        # save new value
        try:
            self._db.users.set_property(username_new, key, value)
        except CursorError as e:
            return self._internal_error(str(e))
        except RuntimeError as e:
            return self._action_permission_denied('Unable to change user as key invalid')

        # set correct response code
        self._event_log("Set %s=%s for user %s" % (key, value, username_new))
        self._set_response_code('200 OK')
        return self._action_userlist()

    def _action_userdel(self):
        """ Delete a user [ADMIN ONLY] """

        if self.username != 'admin':
            return self._action_permission_denied('Unable to remove user as not admin')
        username_new = self.qs_get.get('username_new', [None])[0]
        if not username_new:
            return self._action_permission_denied('Unable to change user as no data')

        try:
            exists = self._db.users.is_enabled(username_new)
        except CursorError as e:
            return self._internal_error(str(e))
        if not exists:
            self._set_response_code('400 Bad Request')
            return self._action_userlist("No entry with username %s" % username_new)
        try:
            self._db.users.remove(username_new)
        except CursorError as e:
            return self._internal_error(str(e))
        self._event_log("Deleted user %s" % username_new)
        self._set_response_code('200 OK')
        return self._action_userlist('Deleted user')

    def _action_usermod(self):
        """ Change details about the current user """

        if self.is_locked:
            return self._action_permission_denied('Unable to change user as account locked')
        if not 'password_new' in self.fields:
            return self._action_permission_denied('Unable to change user as no data')
        if not 'password_old' in self.fields:
            return self._action_permission_denied('Unable to change user as no data')
        if not 'name' in self.fields:
            return self._action_permission_denied('Unable to change user as no data')
        if not 'email' in self.fields:
            return self._action_permission_denied('Unable to change user as no data')
        try:
            auth = self._db.users.verify(self.username, self.fields['password_old'].value)
        except CursorError as e:
            return self._internal_error(str(e))
        if not auth:
            return self._action_login('Incorrect existing password')

        # check password
        password = self.fields['password_new'].value
        pw_check = _password_check(password)
        if pw_check:
            self._set_response_code('400 Bad Request')
            return self._action_profile(pw_check)

        # check email
        email = self.fields['email'].value
        email_check = _email_check(email)
        if email_check:
            return self._action_profile(email_check)

        # verify name
        name = self.fields['name'].value
        if len(name) < 3:
            self._set_response_code('400 Bad Request')
            return self._action_profile('Name invalid')
        try:
            self._db.users.update(self.username, password, name, email)
        except CursorError as e:
            return self._internal_error(str(e))
        self.session_cookie['password'] = _password_hash(password)
        self._event_log('Changed password')
        self._set_response_code('200 OK')
        return self._action_profile('Updated profile')

    def _action_profile(self, msg=''):
        """
        Allows the normal user to change details about the account,
        and also the admin user to add or remove user accounts.
         """

        # security check
        if self.is_locked:
            return self._action_permission_denied('Unable to view profile as account locked')

        html = """
<p>%s</p>
<h1>Modify User</h1>
<p>
A good password consists of upper and lower case with numbers.
</p>
<form method="post" action="wsgi.py?action=usermod">
<table class="upload">
<tr>
<th class="upload">Current Password:</th>
<td><input type="password" name="password_old" required></td>
</tr>
<tr>
<th class="upload">New Password:</th>
<td><input type="password" name="password_new" required></td>
</tr>
<tr>
<th class="upload">Vendor Name:</th>
<td><input type="text" name="name" value="%s" required></td>
</tr>
<tr>
<th class="upload">Contact Email:</th>
<td><input type="text" name="email" value="%s" required></td>
</tr>
</table>
<input type="submit" class="submit" value="Modify">
</form>
"""

        # auth check
        try:
            item = self._db.users.get_item(self.username)
        except CursorError as e:
            return self._internal_error(str(e))
        if not item:
            return self._action_login('Invalid username query')

        # add defaults
        if not item.display_name:
            item.display_name = "Example Name"
        if not item.email:
            item.email = "info@example.com"

        html = html % (msg, item.display_name, item.email)

        # add suitable warning
        if self.username == 'admin':
            html += '<p>The email address set here will be used as the signing key for all firmware and metadata.</p>'

        self._set_response_code('200 OK')
        return self._gen_header('Modify User') + html + self._gen_footer()

    def _action_userlist(self, msg=None):
        """
        Show a list of all users
        """

        if self.username != 'admin':
            return self._action_permission_denied('Unable to show event log for non-admin user')
        html = "<h1>User List</h1>"
        if msg:
            html += '<p>%s</p>' % msg
        html += '<table class="history">'
        html += '<tr>'
        html += '<th>Username</th>'
        html += '<th>Password</th>'
        html += '<th>Name</th>'
        html += '<th>Email</th>'
        html += '<th>Group</th>'
        html += '<th>Actions</th>'
        html += '</tr>'
        try:
            items = self._db.users.get_items()
        except CursorError as e:
            return self._internal_error(str(e))
        for item in items:
            if item.username == 'admin':
                button = ''
            else:
                button = "<form method=\"get\" action=\"wsgi.py\">" \
                         "<input type=\"hidden\" name=\"action\" value=\"userdel\"/>" \
                         "<input type=\"hidden\" name=\"username_new\" value=\"%s\"/>" \
                         "<button class=\"fixedwidth\">Delete</button>" \
                         "</form>" % item.username
                if not item.is_enabled:
                    button += "<form method=\"get\" action=\"wsgi.py\">" \
                              "<input type=\"hidden\" name=\"action\" value=\"userinc\"/>" \
                              "<input type=\"hidden\" name=\"username_new\" value=\"%s\"/>" \
                              "<input type=\"hidden\" name=\"key\" value=\"%s\"/>" \
                              "<button class=\"fixedwidth\">Enable</button>" \
                              "</form>" % (item.username, 'enabled')
                else:
                    button += "<form method=\"get\" action=\"wsgi.py\">" \
                              "<input type=\"hidden\" name=\"action\" value=\"userdec\"/>" \
                              "<input type=\"hidden\" name=\"username_new\" value=\"%s\"/>" \
                              "<input type=\"hidden\" name=\"key\" value=\"%s\"/>" \
                              "<button class=\"fixedwidth\">Disable</button>" \
                              "</form>" % (item.username, 'enabled')
                if not item.is_locked:
                    button += "<form method=\"get\" action=\"wsgi.py\">" \
                              "<input type=\"hidden\" name=\"action\" value=\"userinc\"/>" \
                              "<input type=\"hidden\" name=\"username_new\" value=\"%s\"/>" \
                              "<input type=\"hidden\" name=\"key\" value=\"%s\"/>" \
                              "<button class=\"fixedwidth\">Lock</button>" \
                              "</form>" % (item.username, 'locked')
                else:
                    button += "<form method=\"get\" action=\"wsgi.py\">" \
                              "<input type=\"hidden\" name=\"action\" value=\"userdec\"/>" \
                              "<input type=\"hidden\" name=\"username_new\" value=\"%s\"/>" \
                              "<input type=\"hidden\" name=\"key\" value=\"%s\"/>" \
                              "<button class=\"fixedwidth\">Unlock</button>" \
                              "</form>" % (item.username, 'locked')
                if not item.is_qa:
                    button += "<form method=\"get\" action=\"wsgi.py\">" \
                              "<input type=\"hidden\" name=\"action\" value=\"userinc\"/>" \
                              "<input type=\"hidden\" name=\"username_new\" value=\"%s\"/>" \
                              "<input type=\"hidden\" name=\"key\" value=\"%s\"/>" \
                              "<button class=\"fixedwidth\">+QA</button>" \
                              "</form>" % (item.username, 'qa')
                else:
                    button += "<form method=\"get\" action=\"wsgi.py\">" \
                              "<input type=\"hidden\" name=\"action\" value=\"userdec\"/>" \
                              "<input type=\"hidden\" name=\"username_new\" value=\"%s\"/>" \
                              "<input type=\"hidden\" name=\"key\" value=\"%s\"/>" \
                              "<button class=\"fixedwidth\">-QA</button>" \
                              "</form>" % (item.username, 'qa')
            html += '<tr>'
            html += "<td>%s</td>\n" % item.username
            html += "<td>%s&hellip;</td>\n" % item.password[0:8]
            html += "<td>%s</td>\n" % item.display_name
            html += "<td>%s</td>\n" % item.email
            html += "<td>%s</td>\n" % item.qa_group
            html += "<td>%s</td>\n" % button
            html += '</tr>'

        # add new user form
        html += "<tr>"
        html += "<form method=\"post\" action=\"wsgi.py?action=useradd\">"
        html += "<td><input type=\"text\" size=\"8\" name=\"username_new\" placeholder=\"username\" required></td>"
        html += "<td><input type=\"password\" size=\"8\" name=\"password_new\" placeholder=\"password\" required></td>"
        html += "<td><input type=\"text\" size=\"14\" name=\"name\" placeholder=\"Example Name\" required></td>"
        html += "<td><input type=\"text\" size=\"14\" name=\"email\" placeholder=\"info@example.com\" required></td>"
        html += "<td><input type=\"text\" size=\"8\" name=\"qa_group\" placeholder=\"example\" required></td>"
        html += "<td><input type=\"submit\" style=\"width: 6em\" value=\"Add\"></td>"
        html += "</form>"
        html += "</tr>\n"
        html += '</table>'

        self._set_response_code('200 OK')
        return self._gen_header('User List') + html + self._gen_footer()

    def _action_eventlog(self):
        """
        Show an event log of user actions.
        """
        if self.username != 'admin':
            return self._action_permission_denied('Unable to show event log for non-admin user')

        # get parameters
        start = self.qs_get.get('start', [0])[0]
        length = self.qs_get.get('length', [0])[0]
        if length == 0:
            length = 20

        # get the page selection correct
        eventlog_len = self._db.eventlog.size()
        nr_pages = int(math.ceil(eventlog_len / float(length)))

        html = """
<h1>Event Log</h1>
<table class="history">
<tr>
<th>Timestamp</th>
<th>Address</th>
<th>User</th>
<th></th>
<th>Message</th>
</tr>
"""
        try:
            items = self._db.eventlog.get_items(int(start), int(length))
        except CursorError as e:
            return self._internal_error(str(e))
        if len(items) == 0:
            return self._internal_error('No event log available!')
        for item in items:
            html += '<tr>'
            html += '<td class="history">%s</td>' % str(item.timestamp).split('.')[0]
            html += '<td class="history">%s</td>' % item.address
            html += '<td class="history">%s</td>' % item.username
            if item.is_important == 1:
                html += '<td class="history">&#x272a;</td>'
            else:
                html += '<td class="history"></td>'
            html += '<td class="history">%s</td>' % item.message
            html += '</tr>\n'
        html += '</table>'

        # limit this to keep the UI sane
        if nr_pages > 20:
            nr_pages = 20

        for i in range(nr_pages):
            if int(start) == i * int(length):
                html += '%i ' % (i + 1)
            else:
                html += '<a href="?action=eventlog&start=%i&length=%s">%i</a> ' % (i * int(length), int(length), i + 1)

        return self._gen_header('Event Log') + html + self._gen_footer()

    def _action_firmware(self):
        """
        The main page that shows existing firmware and also allows the
        user to add new firmware.
        """

        html = """
<h1>Introduction</h1>
LVFS provides functionality for hardware vendors to submit packaged firmware updates.
There is no charge to vendors for the hosting or distribution of content.
"""

        html += """
<h2>Add New Firmware</h2>
<p>By uploading a firmware file you must agree that:</p>
<ul>
<li>You are legally permitted to submit the firmware</li>
<li>The submitted firmware file is permitted to be mirrored by our site</li>
<li>We can extract and repackage the information inside the metainfo file</li>
<li>The firmware installation must complete without requiring user input</li>
<li>The update must not be malicious e.g. be a virus or to exploit security issues</li>
</ul>
"""

        html += """
<form action="wsgi.php?action=upload" method="post" enctype="multipart/form-data">
<table class="upload">
"""

        # can the user upload directly to stable
        if self.qa_capability:
            html += '<tr>'
            html += '<th width="150px" class="upload"><label for="target">Target:</label></th>'
            html += '<td>'
            html += '<select name="target" class="fixedwidth" required>'
            html += '<option value="private">Private</option>'
            html += '<option value="embargo">Embargoed</option>'
            html += '<option value="testing">Testing</option>'
            html += '<option value="stable">Stable</option>'
            html += '</select>'
            html += '</td>'
            html += '</tr>'
        else:
            html += '<tr>'
            html += '<th width="150px" class="upload"><label for="target">Target:</label></th>'
            html += '<td>'
            html += '<select name="target" class="fixedwidth" required>'
            html += '<option value="private">Private</option>'
            html += '<option value="embargo">Embargoed</option>'
            html += '</select>'
            html += '</td>'
            html += '</tr>'

        # all enabled users can upload
        html += '<tr>'
        html += '<th width="150px" class="upload"><label for="file">Cab Archive:</label></th>'
        html += '<td><input type="file" name="file" required/></td>'
        html += '</tr>'
        html += '</table>'

        html += '<input type="submit" class="submit" value="Upload"/>'
        html += '</form>'
        html += '<p>'
        html += ' Updates normally go through these stages: '
        html += '<a href="#" title="The private target keeps the firmware secret ' \
                'and is only downloadable from this admin console. An admin or ' \
                'QA user can move the firmware to either embargo, testing or ' \
                'stable.">Private</a> &#8594; '
        html += '<a href="#" title="The embargo target makes the firmware ' \
                'available to users knowing a secret metdata URL. An admin or ' \
                'QA user can move the firmware to testing when the hardware has ' \
                'been released.">Embargoed</a> &#8594; '
        html += '<a href="#" title="The testing target makes the firmware ' \
                'available to some users. An admin or QA user can move the ' \
                'firmware to stable when testing is complete.">Testing</a> &#8594; '
        html += '<a href="#" title="The stable target makes the firmware ' \
                'available to all users. Make sure the firmware has been ' \
                'carefully tested before using this target.">Stable</a>'
        html += '</p>'
        html += '</table>'
        return self._gen_header('Home') + html + self._gen_footer()

    def _action_existing(self):
        """
        Show all previsouly uploaded firmware for this user.
        """
        html = '<h1>Existing Firmware</h1>'
        try:
            items = self._db.firmware.get_items()
        except CursorError as e:
            return self._internal_error(str(e))
        if len(items) > 0:
            html += "<p>These firmware files have been uploaded to the " \
                    "&lsquo;%s&rsquo; QA group:</p>" % self.qa_group
            html += "<table class=\"history\">"
            html += "<tr>"
            html += "<th>Submitted</td>"
            html += "<th>Name</td>"
            html += "<th>Version</td>"
            html += "<th>Target</td>"
            html += "<th></td>"
            html += "</tr>\n"
            for item in items:

                # admin can see everything
                if self.username != 'admin':
                    if item.qa_group != self.qa_group:
                        continue

                buttons = "<form method=\"get\" action=\"wsgi.py\">" \
                          "<input type=\"hidden\" name=\"action\" value=\"fwshow\"/>" \
                          "<input type=\"hidden\" name=\"id\" value=\"%s\"/>" \
                          "<button class=\"fixedwidth\">Details</button>" \
                          "</form>" % item.fwid
                html += '<tr>'
                html += "<td>%s</td>" % item.timestamp
                html += "<td>%s</td>" % item.md_name
                if not item.md_version_display or item.md_version == item.md_version_display:
                    html += "<td>%s</td>" % item.md_version
                else:
                    html += "<td>%s [%s]</td>" % (item.md_version_display, item.md_version)
                html += "<td>%s</td>" % item.target
                html += "<td>%s</td>" % buttons
                html += '</tr>\n'
            html += "</table>"
        else:
            html += "<p>No firmware has been uploaded to the " \
                    "&lsquo;%s&rsquo; QA group yet.</p>" % self.qa_group
        return self._gen_header('Existing') + html + self._gen_footer()

    def _update_metadata_from_fn(self, fwobj, fn):
        """
        Re-parses the .cab file and updates the database version.
        """

        # load cab file
        arc = cabarchive.CabArchive()
        arc.set_decompressor(CABEXTRACT_CMD)
        try:
            arc.parse_file(fn)
        except cabarchive.CorruptionError as e:
            return self._internal_error('Invalid file type: %s' % str(e))

        # parse the MetaInfo file
        cf = arc.find_file("*.metainfo.xml")
        if not cf:
            return self._internal_error('The firmware file had no valid metadata')
        app = appstream.Component()
        try:
            app.parse(str(cf.contents))
        except appstream.ParseError as e:
            return self._internal_error('The metadata could not be parsed: ' + cgi.escape(str(e)))

        # parse the inf file
        cf = arc.find_file("*.inf")
        if not cf:
            return self._internal_error('The firmware file had no valid inf file')
        cfg = InfParser()
        cfg.read_data(cf.contents)
        try:
            tmp = cfg.get('Version', 'DriverVer')
        except ConfigParser.NoOptionError as e:
            return self._internal_error('The inf file Version:DriverVer was missing')
        driver_ver = tmp.split(',')
        if len(driver_ver) != 2:
            return self._internal_error('The inf file Version:DriverVer was invalid')

        # update the descriptions
        fwobj.md_release_description = app.releases[0].description
        fwobj.md_description = app.description
        fwobj.md_version_display = driver_ver[1]
        self._db.firmware.update(fwobj)
        return None

    def _action_metadata_rebuild(self):
        """
        Forces a rebuild of all metadata.
        """
        if self.username != 'admin':
            return self._action_permission_denied('Only admin is allowed to force-rebuild firmware')

        # go through existing files and fix descriptions
        try:
            items = self._db.firmware.get_items()
        except CursorError as e:
            return self._internal_error(str(e))
        for fn in glob.glob(os.path.join(UPLOAD_DIR, "*.cab")):
            fwupd = os.path.basename(fn).split('-')[0]
            for fwobj in items:
                if fwobj.fwid == fwupd:
                    err_page = self._update_metadata_from_fn(fwobj, fn)
                    if err_page:
                        return err_page

        # update metadata
        try:
            self.update_metadata(targets=['stable', 'testing'], qa_group='')
        except NoKeyError as e:
            return self._upload_failed('Failed to sign metadata: ' + cgi.escape(str(e)))
        return self._action_metadata()

    def _action_metadata(self):
        """
        Show all metadata available to this usr.
        """
        html = '<h1>Metadata</h1>'
        html += "<p>The metadata URLs can be used in <code>/etc/fwupd.conf</code> " \
                "to perform end-to-end tests. It is important to not share the " \
                "QA Group URL with external users if you want the embargoed " \
                "firmware to remain hidden from the public.</p>" \
                "<p>You also may need to do <code>fwupdmgr refresh</code> on each " \
                "client to show new updates.</p>"
        html += '<table class=\"history\">'
        html += '<tr>'
        html += '<th>Description</t>'
        html += '<th>Private</th>'
        html += '<th>Embargo</th>'
        html += '<th>Testing</th>'
        html += '<th>Stable</th>'
        html += '<th>URL</th>'
        html += '</tr>'
        html += '<tr>'
        html += '<td>QA Group &lsquo;%s&rsquo;</td>' % self.qa_group
        html += '<td>No</td>'
        html += '<td><b>Yes</b></td>'
        html += '<td><b>Yes</b></td>'
        html += '<td><b>Yes</b></td>'
        qa_url = 'firmware-%s.xml.gz' % _qa_hash(self.qa_group)
        qa_disp = 'firmware-%s&hellip;.xml.gz' % _qa_hash(self.qa_group)[0:8]
        html += '<td><a href="downloads/%s">%s</td>' % (qa_url, qa_disp)
        html += '</tr>\n'
        html += '<tr>'
        html += '<td>Testing</td>'
        html += '<td>No</td>'
        html += '<td>No</td>'
        html += '<td><b>Yes</b></td>'
        html += '<td><b>Yes</b></td>'
        html += '<td><a href="downloads/firmware-testing.xml.gz">firmware-testing.xml.gz</td>'
        html += '</tr>\n'
        html += '<tr>'
        html += '<td>Stable</td>'
        html += '<td>No</td>'
        html += '<td>No</td>'
        html += '<td>No</td>'
        html += '<td><b>Yes</b></td>'
        html += '<td><a href="downloads/firmware.xml.gz">firmware.xml.gz</td>'
        html += '</tr>\n'
        html += '</table>'

        # admin only actions
        if self.username == 'admin':
            html += '<h2>Actions</h2>'
            html += "<form method=\"get\" action=\"wsgi.py\">" \
                    "<input type=\"hidden\" name=\"action\" value=\"metadata_rebuild\"/>" \
                    "<button>Force Rebuild Metadata</button>" \
                    "</form>"

        return self._gen_header('Metadata') + html + self._gen_footer()

    def _action_permission_denied(self, msg=None):
        """ The user tried to do something they did not have privs for """

        html = """
<h1>Error: Permission Denied</h1>
<p>Sorry Dave, I can't let you do that&hellip;</p>
"""
        # set correct response code
        self._event_log("Permission denied: %s" % msg, is_important=True)
        self._set_response_code('401 Unauthorized')
        return self._gen_header('Permission Denied') + html + self._gen_footer()

    def _upload_failed(self, msg=''):
        """ The file upload failed for some reason """

        html = """
<h1>Result: Failed</h1>
<p>%s</p>
"""
        html = html % msg
        # set correct response code
        self._set_response_code('400 Bad Request')
        return self._gen_header('Upload Failed') + html + self._gen_footer()

    def _internal_error(self, admin_only_msg=''):
        """ The file upload failed for some reason """

        html = """
<h1>Internal Error</h1>
<p>%s</p>
"""
        if self.username == 'admin':
            html = html % admin_only_msg
        else:
            html = html % 'No failure details available for this privilege level.'
        # set correct response code
        self._set_response_code('406 Not Acceptable')
        return self._gen_header('Internal Error') + html + self._gen_footer()

    def _upload_success(self):
        """ A file was successfully uploaded to the LVFS """

        html = """
<h1>Result: Success</h1>
 The firmware file was successfully uploaded and the metadata has been updated.
"""
        # set correct response code
        self._set_response_code('201 Created')
        return self._gen_header('Upload Success') + html + self._gen_footer()

    def _action_fwdelete(self):
        """ Delete a firmware entry and also delete the file from disk """

        # get input
        fwid = self.qs_get.get('id', [None])[0]
        if not fwid:
            return self._upload_failed("No ID specified" % fwid)

        # check firmware exists in database
        try:
            item = self._db.firmware.get_item(fwid)
        except CursorError as e:
            return self._internal_error(str(e))
        if not item:
            return self._upload_failed("No firmware file with hash %s exists" % fwid)
        if self.username != 'admin' and item.qa_group != self.qa_group:
            return self._action_permission_denied("No QA access to %s" % fwid)

        # only QA users can delete once the firmware has gone stable
        if not self.qa_capability and item.target == 'stable':
            return self._action_permission_denied('Unable to delete stable firmware as not QA')

        # delete id from database
        try:
            self._db.firmware.remove(fwid)
        except CursorError as e:
            return self._internal_error(str(e))

        # delete file(s)
        for loc in [UPLOAD_DIR, DOWNLOAD_DIR]:
            path = os.path.join(loc, item.filename)
            if os.path.exists(path):
                os.remove(path)

        # update everything
        try:
            self.update_metadata(targets=['stable', 'testing'], qa_group='')
        except NoKeyError as e:
            return self._upload_failed('Failed to sign metadata: ' + cgi.escape(str(e)))

        self._event_log("Deleted firmware %s" % fwid)
        self._set_response_code('200 OK')
        return self._action_firmware()

    def _action_fwshow(self):
        """ Show profile information """

        # get input
        fwid = self.qs_get.get('id', [None])[0]
        if not fwid:
            return self._internal_error('No ID specified')

        # get details about the firmware
        try:
            item = self._db.firmware.get_item(fwid)
        except CursorError as e:
            return self._internal_error(str(e))
        if not item:
            return self._action_login('No firmware matched!')

        # we can only view our own firmware, unless admin
        qa_group = item.qa_group
        if qa_group != self.qa_group and self.username != 'admin':
            return self._action_permission_denied('Unable to view other vendor firmware')
        if not qa_group:
            embargo_url = 'downloads/firmware.xml.gz'
            qa_group = 'None'
        else:
            embargo_url = 'downloads/firmware-%s.xml.gz' % _qa_hash(qa_group)
        file_uri = 'downloads/' + item.filename

        buttons = ''
        if self.qa_capability or item.target == 'private':
            buttons += "<form method=\"get\" action=\"wsgi.py\">" \
                       "<input type=\"hidden\" name=\"action\" value=\"fwdelete\"/>" \
                       "<input type=\"hidden\" name=\"id\" value=\"%s\"/>" \
                       "<button class=\"fixedwidth\">Delete</button>" \
                       "</form>" % fwid
        if self.qa_capability:
            if item.target == 'private':
                buttons += "<form method=\"get\" action=\"wsgi.py\">" \
                           "<input type=\"hidden\" name=\"action\" value=\"fwpromote\"/>" \
                           "<input type=\"hidden\" name=\"target\" value=\"embargo\"/>" \
                           "<input type=\"hidden\" name=\"id\" value=\"%s\"/>" \
                           "<button class=\"fixedwidth\">&#8594; Embargo</button>" \
                           "</form>" % fwid
            elif item.target == 'embargo':
                buttons += "<form method=\"get\" action=\"wsgi.py\">" \
                           "<input type=\"hidden\" name=\"action\" value=\"fwpromote\"/>" \
                           "<input type=\"hidden\" name=\"target\" value=\"testing\"/>" \
                           "<input type=\"hidden\" name=\"id\" value=\"%s\"/>" \
                           "<button class=\"fixedwidth\">&#8594; Testing</button>" \
                           "</form>" % fwid
            elif item.target == 'testing':
                buttons += "<form method=\"get\" action=\"wsgi.py\">" \
                           "<input type=\"hidden\" name=\"action\" value=\"fwpromote\"/>" \
                           "<input type=\"hidden\" name=\"target\" value=\"stable\"/>" \
                           "<input type=\"hidden\" name=\"id\" value=\"%s\"/>" \
                           "<button class=\"fixedwidth\">&#8594; Stable</button>" \
                           "</form>" % fwid

        html = '<h1>%s</h1>' % item.md_name
        html += '<p>%s</p>' % item.md_summary
        html += '<table class="history">'
        html += '<tr><th>ID</th><td>%s</td></tr>' % item.md_id
        html += '<tr><th>Filename</th><td><a href=\"%s\">%s</a></td></tr>' % (file_uri, item.filename)
        html += '<tr><th>Device GUID</th><td>%s</td></tr>' % item.md_guid
        if not item.md_version_display or item.md_version == item.md_version_display:
            html += '<tr><th>Version</th><td>%s</td></tr>' % item.md_version
        else:
            html += '<tr><th>Version</th><td>%s [%s]</td></tr>' % (item.md_version_display, item.md_version)
        html += '<tr><th>Current Target</th><td>%s</td></tr>' % item.target
        html += '<tr><th>Submitted</th><td>%s</td></tr>' % item.timestamp
        html += '<tr><th>QA Group</th><td><a href="%s">%s</a></td></tr>' % (embargo_url, qa_group)
        html += '<tr><th>Uploaded from</th><td>%s</td></tr>' % item.addr
        html += '<tr><th>Downloads</th><td>%i</td></tr>' % item.download_cnt
        html += '<tr><th>Actions</th><td>%s</td></tr>' % buttons
        html += '</table>'

        # set correct response code
        self._set_response_code('200 OK')
        return self._gen_header('Firmware Details') + html + self._gen_footer()

    def _action_fwpromote(self):
        """
        Promote or demote a firmware file from one target to another,
        for example from testing to stable, or stable to testing.
         """

        # check is QA
        if not self.qa_capability:
            return self._action_permission_denied('Unable to promote as not QA')

        # get input
        fwid = self.qs_get.get('id', [None])[0]
        if not fwid:
            return self._internal_error('No ID specified')
        target = self.qs_get.get('target', [None])[0]
        if not fwid:
            return self._internal_error('No target specified')

        # check valid
        if target not in ['stable', 'testing', 'private', 'embargo']:
            return self._internal_error("Target %s invalid" % target)

        # check firmware exists in database
        try:
            self._db.firmware.set_target(fwid, target)
        except CursorError as e:
            return self._internal_error(str(e))
        # set correct response code
        self._event_log("Moved firmware %s to %s" % (fwid, target))

        # update everything
        try:
            self.update_metadata(targets=['stable', 'testing'], qa_group='')
        except NoKeyError as e:
            return self._upload_failed('Failed to sign metadata: ' + cgi.escape(str(e)))

        return self._action_fwshow()

    def _action_upload(self):
        """ Upload a .cab file to the LVFS service """

        # not correct parameters
        if not 'target' in self.fields:
            return self._upload_failed('No target')
        if not 'file' in self.fields:
            return self._upload_failed('No file')

        # can the user upload directly to stable
        if self.fields['target'].value in ['stable', 'testing']:
            if not self.qa_capability:
                return self._action_permission_denied('Unable to upload to this target as not QA user')

        # check size < 50Mb
        fileitem = self.fields['file']
        if not fileitem.file:
            return self._upload_failed('No file object')
        data = fileitem.file.read()
        if len(data) > 50000000:
            self._set_response_code('413 Payload Too Large')
            return self._upload_failed('File too large, limit is 50Mb')
        if len(data) == 0:
            return self._upload_failed('File has no content')
        if len(data) < 1024:
            return self._upload_failed('File too small, mimimum is 1k')

        # parse the file
        arc = cabarchive.CabArchive()
        arc.set_decompressor(CABEXTRACT_CMD)
        try:
            arc.parse(data)
        except cabarchive.CorruptionError as e:
            self._set_response_code('415 Unsupported Media Type')
            return self._upload_failed('Invalid file type: %s' % str(e))
        except cabarchive.NotSupportedError as e:
            self._set_response_code('415 Unsupported Media Type')
            return self._upload_failed('The file is unsupported: %s' % str(e))

        # check .inf exists
        cf = arc.find_file("*.inf")
        if not cf:
            return self._upload_failed('The firmware file had no valid inf file')

        # check the file does not have any missing fields
        if cf.contents.find('FIXME') != -1:
            return self._upload_failed("The inf file was not complete; "
                                       "Any FIXME text must be replaced with the correct values.")

        # check .inf file is valid
        cfg = InfParser()
        cfg.read_data(cf.contents)
        try:
            tmp = cfg.get('Version', 'Class')
        except ConfigParser.NoOptionError as e:
            return self._upload_failed('The inf file Version:Class was missing')
        if not tmp == 'Firmware':
            return self._upload_failed('The inf file Version:Class was invalid')
        try:
            tmp = cfg.get('Version', 'ClassGuid')
        except ConfigParser.NoOptionError as e:
            return self._upload_failed('The inf file Version:ClassGuid was missing')
        if not tmp == '{f2e7dd72-6468-4e36-b6f1-6488f42c1b52}':
            return self._upload_failed('The inf file Version:ClassGuid was invalid')
        try:
            tmp = cfg.get('Version', 'DriverVer')
        except ConfigParser.NoOptionError as e:
            return self._upload_failed('The inf file Version:DriverVer was missing')
        driver_ver = tmp.split(',')
        if len(driver_ver) != 2:
            return self._upload_failed('The inf file Version:DriverVer was invalid')

        # check metainfo exists
        cf = arc.find_file("*.metainfo.xml")
        if not cf:
            return self._upload_failed('The firmware file had no valid metadata')

        # parse the MetaInfo file
        app = appstream.Component()
        try:
            app.parse(str(cf.contents))
            app.validate()
        except appstream.ParseError as e:
            return self._upload_failed('The metadata could not be parsed: ' + cgi.escape(str(e)))
        except appstream.ValidationError as e:
            return self._upload_failed('The metadata file did not validate: ' + cgi.escape(str(e)))

        # check the file does not have any missing fields
        if cf.contents.find('FIXME') != -1:
            return self._upload_failed("The metadata file was not complete; "
                                       "Any FIXME text must be replaced with the correct values.")

        # check the file does not already exist
        fwid = hashlib.sha1(data).hexdigest()
        try:
            item = self._db.firmware.get_item(fwid)
        except CursorError as e:
            return self._internal_error(str(e))
        if item:
            self._set_response_code('422 Entity Already Exists')
            return self._upload_failed("A firmware file with hash %s already exists" % fwid)

        # check the guid and version does not already exist
        try:
            items = self._db.firmware.get_items()
        except CursorError as e:
            return self._internal_error(str(e))
        for item in items:
            if item.md_guid == app.provides[0].value and item.md_version == app.releases[0].version:
                self._set_response_code('422 Entity Already Exists')
                return self._upload_failed("A firmware file for this version already exists")

        # check the ID hasn't been reused by a different GUID
        for item in items:
            if item.md_id == app.id and not item.md_guid == app.provides[0].value:
                self._set_response_code('422 Entity Already Exists')
                return self._upload_failed("The %s ID has already been used by GUID %s" % (item.md_id, item.md_guid))

        # only save if we passed all tests
        basename = os.path.basename(fileitem.filename)
        new_filename = fwid + '-' + basename
        if not os.path.exists(UPLOAD_DIR):
            os.mkdir(UPLOAD_DIR)
        open(os.path.join(UPLOAD_DIR, new_filename), 'wb').write(data)
        print "wrote %i bytes to %s" % (len(data), new_filename)

        # get the contents checksum
        fw_data = arc.find_file('*.bin')
        if not fw_data:
            fw_data = arc.find_file('*.cap')
        if not fw_data:
            return self._upload_failed('No firmware found in the archive: ' + cgi.escape(str(e)))
        checksum_contents = hashlib.sha1(fw_data.contents).hexdigest()

        # add the detached signature
        try:
            affidavit = self.create_affidavit()
        except NoKeyError as e:
            return self._upload_failed('Failed to sign archive: ' + cgi.escape(str(e)))
        cff = cabarchive.CabFile(fw_data.filename + '.asc',
                                 affidavit.create(fw_data.contents))
        arc.add_file(cff)

        # export the new archive and get the checksum
        cab_data = arc.save(compressed=True)
        checksum_container = hashlib.sha1(cab_data).hexdigest()

        # dump to a file
        if not os.path.exists(DOWNLOAD_DIR):
            os.mkdir(DOWNLOAD_DIR)
        fn = os.path.join(DOWNLOAD_DIR, new_filename)
        open(fn, 'wb').write(cab_data)

        # add to database
        target = self.fields['target'].value
        try:
            fwobj = LvfsFirmware()
            fwobj.qa_group = self.qa_group
            fwobj.addr = self.client_address
            fwobj.filename = new_filename
            fwobj.fwid = fwid
            fwobj.target = target
            fwobj.md_id = app.id
            fwobj.md_guid = app.provides[0].value
            fwobj.md_version = app.releases[0].version
            fwobj.md_version_display = driver_ver[1]
            fwobj.md_name = app.name
            fwobj.md_summary = app.summary
            fwobj.md_checksum_contents = checksum_contents
            fwobj.md_release_description = app.releases[0].description
            fwobj.md_release_timestamp = app.releases[0].timestamp
            fwobj.md_developer_name = app.developer_name
            fwobj.md_metadata_license = app.metadata_license
            fwobj.md_project_license = app.project_license
            fwobj.md_url_homepage = app.urls['homepage']
            fwobj.md_description = app.description
            fwobj.md_checksum_container = checksum_container
            fwobj.md_filename_contents = fw_data.filename
            self._db.firmware.add(fwobj)
        except CursorError as e:
            return self._internal_error(str(e))
        # set correct response code
        self._event_log("Uploaded file %s to %s" % (new_filename, target))
        self._set_response_code('201 Created')

        # ensure up to date
        try:
            self.update_metadata(targets=['stable', 'testing'], qa_group='')
            if target in ['stable', 'testing']:
                self.update_metadata(targets=[target])
            elif target == 'embargo':
                self.update_metadata(qa_group=self.qa_group)
        except NoKeyError as e:
            return self._upload_failed('Failed to sign metadata: ' + cgi.escape(str(e)))

        return self._upload_success()

    def get_response(self):
        """ Get the correct page using the page POST and GET data """

        # perform anon actions
        action = self.qs_get.get('action', [None])[0]
        if action == 'newaccount':
            return self._action_newaccount()

        # auth check
        if not self.username:
            self._set_response_code('401 Unauthorized')
            return self._action_login()
        try:
            item = self._db.users.get_item(self.username, self.password)
        except CursorError as e:
            return self._internal_error(str(e))
        if not item:
            # log failure
            if self._is_login_from_post:
                self._event_log('Failed login attempt')
            return self._action_login('Incorrect username or password')
        if not item.is_enabled:
            # log failure
            if self._is_login_from_post:
                self._event_log('Failed login attempt (user disabled)')
            return self._action_login('User account has been disabled')
        self.qa_capability = item.is_qa
        self.qa_group = item.qa_group
        self.is_locked = item.is_locked

        # log success
        if self._is_login_from_post:
            self._event_log('Logged on')

        # perform login-required actions
        if action == 'logout':
            self.session_cookie['username']['Path'] = '/'
            self.session_cookie['username']['max-age'] = -1
            self.session_cookie['password']['Path'] = '/'
            self.session_cookie['password']['max-age'] = -1
            self._event_log('Logged out')
            return self._action_login('Successfully logged out. Log in again to perform any vendor actions.')
        elif action == 'profile':
            return self._action_profile()
        elif action == 'analytics':
            return self._action_analytics()
        elif action == 'usermod':
            return self._action_usermod()
        elif action == 'useradd':
            return self._action_useradd()
        elif action == 'userdel':
            return self._action_userdel()
        elif action == 'userinc':
            return self._action_userinc(1)
        elif action == 'userdec':
            return self._action_userinc(0)
        elif action == 'upload':
            return self._action_upload()
        elif action == 'fwdelete':
            return self._action_fwdelete()
        elif action == 'fwpromote':
            return self._action_fwpromote()
        elif action == 'fwshow':
            return self._action_fwshow()
        elif action == 'eventlog':
            return self._action_eventlog()
        elif action == 'userlist':
            return self._action_userlist()
        elif action == 'existing':
            return self._action_existing()
        elif action == 'metadata':
            return self._action_metadata()
        elif action == 'metadata_rebuild':
            return self._action_metadata_rebuild()
        else:
            self.session_cookie['username'] = self.username
            self.session_cookie['username']['Path'] = '/'
            self.session_cookie['username']['max-age'] = 2 * 60 * 60
            self.session_cookie['password'] = self.password
            self.session_cookie['password']['Path'] = '/'
            self.session_cookie['password']['max-age'] = 2 * 60 * 60
            return self._action_firmware()

    def _generate_metadata_kind(self, filename, targets=None, qa_group=None):
        """ Generates AppStream metadata of a specific kind """
        try:
            items = self._db.firmware.get_items()
        except CursorError as e:
            return self._internal_error(str(e))
        store = appstream.Store('lvfs')
        for item in items:

            # filter
            if item.target == 'private':
                continue
            if targets and item.target not in targets:
                continue
            if qa_group and qa_group != item.qa_group:
                continue

            # add component
            app = appstream.Component()
            app.id = item.md_id
            app.kind = 'firmware'
            app.name = item.md_name
            app.summary = item.md_summary
            app.description = item.md_description
            if item.md_url_homepage:
                app.urls['homepage'] = item.md_url_homepage
            app.metadata_license = item.md_metadata_license
            app.project_license = item.md_project_license
            app.developer_name = item.md_developer_name

            # add provide
            if item.md_guid:
                prov = appstream.Provide()
                prov.kind = 'firmware-flashed'
                prov.value = item.md_guid
                app.add_provide(prov)

            # add release
            if item.md_version:
                rel = appstream.Release()
                rel.version = item.md_version
                rel.description = item.md_release_description
                if item.md_release_timestamp:
                    rel.timestamp = item.md_release_timestamp
                rel.checksums = []
                rel.location = 'https://secure-lvfs.rhcloud.com/downloads/' + item.filename
                app.add_release(rel)

                # add container checksum
                if item.md_checksum_container:
                    csum = appstream.Checksum()
                    csum.target = 'container'
                    csum.value = item.md_checksum_container
                    csum.filename = item.filename
                    rel.add_checksum(csum)

                # add content checksum
                if item.md_checksum_contents:
                    csum = appstream.Checksum()
                    csum.target = 'content'
                    csum.value = item.md_checksum_contents
                    csum.filename = item.md_filename_contents
                    rel.add_checksum(csum)

            # add app
            store.add(app)

        # dump to file
        if not os.path.exists(DOWNLOAD_DIR):
            os.mkdir(DOWNLOAD_DIR)
        filename = os.path.join(DOWNLOAD_DIR, filename)
        store.to_file(filename)

        # create .asc file
        affidavit = self.create_affidavit()
        affidavit.create_detached(filename)

        # log
        if targets:
            self._event_log("Generated metadata for %s target" % ', '.join(targets))
        if qa_group:
            self._event_log("Generated metadata for %s QA group" % qa_group)

    def update_metadata(self, targets=None, qa_group=None):
        """ Updates metadata """

        # normal metadata
        if targets:
            for target in targets:
                if target == 'stable':
                    filename = 'firmware.xml.gz'
                    self._generate_metadata_kind(filename, targets=['stable'])
                elif target == 'testing':
                    filename = 'firmware-testing.xml.gz'
                    self._generate_metadata_kind(filename, targets=['stable', 'testing'])
                else:
                    filename = 'firmware-%s.xml.gz' % target
                    self._generate_metadata_kind(filename, targets=[target])

        # each vendor
        if qa_group:
            if qa_group == '':
                try:
                    qa_groups = self._db.firmware.get_qa_groups()
                except CursorError as e:
                    return self._internal_error(str(e))
                for qa_group in qa_groups:
                    filename = 'firmware-%s.xml.gz' % _qa_hash(qa_group)
                    self._generate_metadata_kind(filename, qa_group=qa_group)
            else:
                filename = 'firmware-%s.xml.gz' % _qa_hash(qa_group)
                self._generate_metadata_kind(filename, qa_group=qa_group)

    def init(self, environ):
        """ Set up the website helper with the calling environment """

        # get client address
        if 'HTTP_X_FORWARDED_FOR' in environ:
            self.client_address = environ['HTTP_X_FORWARDED_FOR'].split(',')[-1].strip()
        else:
            self.client_address = environ['REMOTE_ADDR']

        # parse POST data
        if 'POST' == environ['REQUEST_METHOD']:
            self.fields = cgi.FieldStorage(fp=environ['wsgi.input'],
                                           environ=environ)

        # find username / password either from POST or the session cookie
        if self.fields:
            if 'username' in self.fields:
                self.username = self.fields['username'].value
                if 'password' in self.fields:
                    self.password = _password_hash(self.fields['password'].value)
                    self._is_login_from_post = True
        if environ.has_key('HTTP_COOKIE'):
            print environ['HTTP_COOKIE']
            self.session_cookie.load(environ['HTTP_COOKIE'])
            if not self.username and 'username' in self.session_cookie:
                self.username = self.session_cookie['username'].value
            if not self.password and 'password' in self.session_cookie:
                self.password = self.session_cookie['password'].value

        # the data source for our controller
        self._db = LvfsDatabase(environ)

def static_app(fn, start_response, content_type, download=False):
    """ Return a static image or resource """
    if not download:
        path = os.path.join(STATIC_DIR, fn)
    else:
        path = os.path.join(DOWNLOAD_DIR, fn)
    if not os.path.exists(path):
        start_response('404 Not Found', [('content-type', 'text/plain')])
        return ['Not found: ' + path]
    h = open(path, 'rb')
    content = h.read()
    h.close()
    headers = [('content-type', content_type)]
    start_response('200 OK', headers)
    return [content]

def application(environ, start_response):
    """ Main entry point for wsgi """

    # static file
    fn = os.path.basename(environ['PATH_INFO'])
    if fn.endswith(".css"):
        return static_app(fn, start_response, 'text/css')
    if fn.endswith(".svg"):
        return static_app(fn, start_response, 'image/svg+xml')
    if fn.endswith(".png"):
        return static_app(fn, start_response, 'image/png')
    if fn.endswith(".ico"):
        return static_app(fn, start_response, 'image/x-icon')
    if fn.endswith(".js"):
        return static_app(fn, start_response, 'application/javascript')
    if fn.endswith(".xml.gz.asc"):
        return static_app(fn, start_response, 'text/plain', download=True)

    # use a helper class
    w = LvfsWebsite()
    w.qs_get = cgi.parse_qs(environ['QUERY_STRING'])
    w.init(environ)

    # handle files
    if fn.endswith(".cab"):
        try:
            w._db.clients.add_firmware(w.client_address)
            w._db.firmware.increment_filename_cnt(fn)
        except CursorError as e:
            pass
        return static_app(fn, start_response, 'application/vnd.ms-cab-compressed', download=True)
    if fn.endswith(".xml.gz"):
        try:
            w._db.clients.add_metadata(w.client_address)
        except CursorError as e:
            pass
        return static_app(fn, start_response, 'application/gzip', download=True)

    # get response
    response_body = w.get_response()

    # fallback
    if not w.response_code:
        print "WARNING, USING FALLBACK CODE"
        w._set_response_code('200 OK')

    response_headers = [('Content-Type', w.content_type),
                        ('Content-Length', str(len(response_body)))]
    response_headers.extend(("set-cookie", morsel.OutputString())
                            for morsel
                            in w.session_cookie.values())
    print w.response_code, response_headers
    start_response(w.response_code, response_headers)

    return [response_body.encode('utf-8')]

if __name__ == '__main__':
    httpd = make_server('localhost', 8051, application)
    httpd.serve_forever()
